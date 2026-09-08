import React, { useState, useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import {
  Network,
  Activity,
  AlertTriangle,
  Flame,
  ShieldCheck,
  ShieldAlert,
  Search,
  Filter,
  Download,
  Maximize2,
  Minimize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Code2,
  ArrowRight,
  ExternalLink,
  Layers,
  FileCode,
  Info,
  Check,
  Copy,
  Crosshair,
  SlidersHorizontal,
  ChevronRight,
  X
} from 'lucide-react';
import {
  DataFlowNode,
  DataFlowLink,
  DataFlowGraphData,
  ScannedFile,
  SeverityLevel
} from '../types';

interface DataFlowGraphViewProps {
  graphData?: DataFlowGraphData;
  files: ScannedFile[];
  onSelectFile?: (filePath: string, line?: number) => void;
}

type LayoutMode = 'PIPELINE' | 'FORCE' | 'FILE_GROUPS';

export const DataFlowGraphView: React.FC<DataFlowGraphViewProps> = ({
  graphData,
  files,
  onSelectFile
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // States
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('PIPELINE');
  const [selectedNode, setSelectedNode] = useState<DataFlowNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<DataFlowNode | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'ALL' | 'ENDPOINT' | 'CONSUMER' | 'SINK'>('ALL');
  const [onlyTainted, setOnlyTainted] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [selectedPathIds, setSelectedPathIds] = useState<Set<string>>(new Set());

  const safeGraph: DataFlowGraphData = graphData || {
    nodes: [],
    links: [],
    metrics: {
      totalEndpoints: 0,
      totalConsumers: 0,
      totalSinks: 0,
      totalTaintFlows: 0,
      criticalSinksCount: 0,
      filesAnalyzed: 0
    }
  };

  // Filter nodes & links based on user criteria
  const { filteredNodes, filteredLinks } = useMemo(() => {
    let nodes = [...safeGraph.nodes];

    if (onlyTainted) {
      nodes = nodes.filter(n => n.tainted);
    }

    if (filterType !== 'ALL') {
      nodes = nodes.filter(n => n.type === filterType);
    }

    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      nodes = nodes.filter(
        n =>
          n.label.toLowerCase().includes(q) ||
          n.file.toLowerCase().includes(q) ||
          (n.sublabel && n.sublabel.toLowerCase().includes(q)) ||
          (n.sinkType && n.sinkType.toLowerCase().includes(q)) ||
          (n.riskCategory && n.riskCategory.toLowerCase().includes(q))
      );
    }

    const nodeIds = new Set(nodes.map(n => n.id));
    const links = safeGraph.links.filter(l => {
      const sId = typeof l.source === 'string' ? l.source : (l.source as DataFlowNode).id;
      const tId = typeof l.target === 'string' ? l.target : (l.target as DataFlowNode).id;
      return nodeIds.has(sId) && nodeIds.has(tId);
    });

    return { filteredNodes: nodes, filteredLinks: links };
  }, [safeGraph, onlyTainted, filterType, searchTerm]);

  // Compute connected nodes for highlighting upon click
  useEffect(() => {
    if (!selectedNode) {
      setSelectedPathIds(new Set());
      return;
    }

    const activeIds = new Set<string>([selectedNode.id]);
    const linkIds = new Set<string>();

    // Forward traverse (downstream)
    const forwardQueue = [selectedNode.id];
    while (forwardQueue.length > 0) {
      const curr = forwardQueue.shift()!;
      for (const link of safeGraph.links) {
        const s = typeof link.source === 'string' ? link.source : (link.source as DataFlowNode).id;
        const t = typeof link.target === 'string' ? link.target : (link.target as DataFlowNode).id;
        if (s === curr && !activeIds.has(t)) {
          activeIds.add(t);
          linkIds.add(link.id);
          forwardQueue.push(t);
        }
      }
    }

    // Backward traverse (upstream)
    const backwardQueue = [selectedNode.id];
    while (backwardQueue.length > 0) {
      const curr = backwardQueue.shift()!;
      for (const link of safeGraph.links) {
        const s = typeof link.source === 'string' ? link.source : (link.source as DataFlowNode).id;
        const t = typeof link.target === 'string' ? link.target : (link.target as DataFlowNode).id;
        if (t === curr && !activeIds.has(s)) {
          activeIds.add(s);
          linkIds.add(link.id);
          backwardQueue.push(s);
        }
      }
    }

    setSelectedPathIds(activeIds);
  }, [selectedNode, safeGraph.links]);

  // Render D3 graph
  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 960;
    const height = Math.max(580, containerRef.current.clientHeight || 580);

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove(); // Clear previous rendering

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    // Create defs for gradients, glows and arrowheads
    const defs = svg.append('defs');

    // Glow filter for dangerous sinks and tainted paths
    const filterGlow = defs.append('filter').attr('id', 'glow-critical').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    filterGlow.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');
    const feMerge = filterGlow.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arrow markers
    const createMarker = (id: string, color: string) => {
      defs.append('marker')
        .attr('id', id)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 22)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-4L8,0L0,4')
        .attr('fill', color);
    };

    createMarker('arrow-tainted', '#FF3E00');
    createMarker('arrow-safe', '#00E5FF');
    createMarker('arrow-consumer', '#F59E0B');
    createMarker('arrow-neutral', '#666666');

    // Graph Root Group with Zoom Support
    const gRoot = svg.append('g').attr('class', 'graph-root');

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.15, 3.5])
      .on('zoom', (event) => {
        gRoot.attr('transform', event.transform);
      });

    svg.call(zoom);
    zoomBehaviorRef.current = zoom;

    // Clone data for simulation so D3 doesn't mutate props directly
    const simNodes: DataFlowNode[] = filteredNodes.map(d => ({ ...d }));
    const simNodeMap = new Map(simNodes.map(d => [d.id, d]));

    const simLinks: Array<DataFlowLink & { source: DataFlowNode; target: DataFlowNode }> = [];
    for (const link of filteredLinks) {
      const sId = typeof link.source === 'string' ? link.source : (link.source as DataFlowNode).id;
      const tId = typeof link.target === 'string' ? link.target : (link.target as DataFlowNode).id;
      const sNode = simNodeMap.get(sId);
      const tNode = simNodeMap.get(tId);
      if (sNode && tNode) {
        simLinks.push({
          ...link,
          source: sNode,
          target: tNode
        });
      }
    }

    // Position assignments based on layout mode
    if (layoutMode === 'PIPELINE') {
      // Split into 3 columns:
      // Column 1: Endpoints (x = 18% width)
      // Column 2: Consumers (x = 50% width)
      // Column 3: Sinks (x = 82% width)
      const endpoints = simNodes.filter(n => n.type === 'ENDPOINT');
      const consumers = simNodes.filter(n => n.type === 'CONSUMER');
      const sinks = simNodes.filter(n => n.type === 'SINK');

      const distributeY = (items: DataFlowNode[], colX: number) => {
        const total = items.length;
        if (total === 0) return;
        const padding = 70;
        const availableHeight = height - padding * 2;
        const step = total > 1 ? availableHeight / (total - 1) : 0;
        items.forEach((item, idx) => {
          item.x = colX;
          item.y = total === 1 ? height / 2 : padding + idx * step;
          item.fx = item.x;
          item.fy = item.y;
        });
      };

      distributeY(endpoints, width * 0.18);
      distributeY(consumers, width * 0.5);
      distributeY(sinks, width * 0.82);
    } else if (layoutMode === 'FILE_GROUPS') {
      // Cluster by file
      const filesList = Array.from(new Set(simNodes.map(n => n.file)));
      const clusterRadius = Math.min(width, height) * 0.35;
      const center = { x: width / 2, y: height / 2 };

      filesList.forEach((f, fIdx) => {
        const angle = (fIdx / filesList.length) * 2 * Math.PI;
        const clusterX = center.x + clusterRadius * Math.cos(angle);
        const clusterY = center.y + clusterRadius * Math.sin(angle);
        const fileNodes = simNodes.filter(n => n.file === f);

        fileNodes.forEach((n, nIdx) => {
          const subAngle = (nIdx / Math.max(1, fileNodes.length)) * 2 * Math.PI;
          const subR = 60;
          n.x = clusterX + subR * Math.cos(subAngle);
          n.y = clusterY + subR * Math.sin(subAngle);
        });
      });
    }

    // Initialize D3 Force Simulation
    const simulation = d3.forceSimulation(simNodes)
      .force(
        'link',
        d3.forceLink<DataFlowNode, any>(simLinks)
          .id(d => d.id)
          .distance(layoutMode === 'FORCE' ? 120 : 180)
      )
      .force('charge', d3.forceManyBody().strength(layoutMode === 'PIPELINE' ? -50 : -450))
      .force('collide', d3.forceCollide().radius(48).iterations(3));

    if (layoutMode === 'FORCE') {
      simulation.force('center', d3.forceCenter(width / 2, height / 2));
    }

    // Background Column Guides for PIPELINE Mode
    if (layoutMode === 'PIPELINE') {
      const guideData = [
        { label: '1. API ENDPOINTS (SOURCES)', x: width * 0.18, color: '#00E5FF' },
        { label: '2. CONSUMER FUNCTIONS (HANDLERS)', x: width * 0.5, color: '#F59E0B' },
        { label: '3. DANGEROUS SINKS (TARGETS)', x: width * 0.82, color: '#FF3E00' }
      ];

      const guidesGroup = gRoot.append('g').attr('class', 'column-guides').attr('opacity', 0.85);

      guideData.forEach(col => {
        guidesGroup.append('line')
          .attr('x1', col.x)
          .attr('y1', 20)
          .attr('x2', col.x)
          .attr('y2', height - 20)
          .attr('stroke', '#1A1A1A')
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '4 4');

        guidesGroup.append('text')
          .attr('x', col.x)
          .attr('y', 36)
          .attr('text-anchor', 'middle')
          .attr('fill', col.color)
          .attr('font-size', '10.5px')
          .attr('font-family', 'monospace')
          .attr('font-weight', '700')
          .attr('letter-spacing', '0.1em')
          .text(col.label);
      });
    }

    // Links Layer
    const linkGroup = gRoot.append('g').attr('class', 'links-layer');

    const linkPaths = linkGroup.selectAll<SVGPathElement, any>('.graph-link')
      .data(simLinks)
      .enter()
      .append('path')
      .attr('class', 'graph-link transition-opacity duration-200 cursor-pointer')
      .attr('fill', 'none')
      .attr('stroke', d => (d.isTainted ? '#FF3E00' : '#00E5FF'))
      .attr('stroke-width', d => (d.isTainted ? 2.5 : 1.5))
      .attr('stroke-dasharray', d => (d.isTainted ? '6 4' : 'none'))
      .attr('opacity', d => {
        if (!selectedNode) return d.isTainted ? 0.9 : 0.45;
        return selectedPathIds.has(d.source.id) && selectedPathIds.has(d.target.id) ? 1 : 0.15;
      })
      .attr('marker-end', d => (d.isTainted ? 'url(#arrow-tainted)' : 'url(#arrow-safe)'));

    // Animated Taint Flow Effect for Tainted Paths
    linkPaths.filter(d => d.isTainted).style('animation', 'dash 1.2s linear infinite');

    // Nodes Layer
    const nodeGroup = gRoot.append('g').attr('class', 'nodes-layer');

    const nodeG = nodeGroup.selectAll<SVGGElement, DataFlowNode>('.graph-node')
      .data(simNodes)
      .enter()
      .append('g')
      .attr('class', 'graph-node cursor-pointer select-none transition-all duration-150')
      .attr('opacity', d => {
        if (!selectedNode) return 1;
        return selectedPathIds.has(d.id) ? 1 : 0.2;
      })
      .call(
        d3.drag<SVGGElement, DataFlowNode>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            if (layoutMode !== 'PIPELINE') {
              d.fx = null;
              d.fy = null;
            }
          })
      )
      .on('click', (event, d) => {
        event.stopPropagation();
        setSelectedNode(prev => (prev?.id === d.id ? null : d));
      })
      .on('mouseenter', (_, d) => setHoveredNode(d))
      .on('mouseleave', () => setHoveredNode(null));

    // Render node shapes based on category
    nodeG.each(function (d) {
      const g = d3.select(this);
      const isSelected = selectedNode?.id === d.id;

      // Glow effect for tainted or critical nodes
      if (d.tainted || d.type === 'SINK') {
        g.append('circle')
          .attr('r', 24)
          .attr('fill', d.tainted ? 'rgba(255, 62, 0, 0.15)' : 'rgba(245, 158, 11, 0.1)')
          .attr('stroke', d.tainted ? '#FF3E00' : '#F59E0B')
          .attr('stroke-width', 1)
          .attr('stroke-dasharray', '2 2')
          .attr('filter', 'url(#glow-critical)');
      }

      if (d.type === 'ENDPOINT') {
        // Pill Badge for API Endpoints
        const boxWidth = 140;
        const boxHeight = 36;
        g.append('rect')
          .attr('x', -boxWidth / 2)
          .attr('y', -boxHeight / 2)
          .attr('width', boxWidth)
          .attr('height', boxHeight)
          .attr('rx', 6)
          .attr('fill', isSelected ? '#003642' : '#0B1317')
          .attr('stroke', isSelected ? '#00E5FF' : d.tainted ? '#FF3E00' : '#1F3438')
          .attr('stroke-width', isSelected || d.tainted ? 2 : 1.2);

        // HTTP Method Badge Tag
        const methodTag = d.method || 'API';
        const tagColor = methodTag === 'POST' ? '#3B82F6' : methodTag === 'DELETE' ? '#EF4444' : '#10B981';
        g.append('rect')
          .attr('x', -boxWidth / 2 + 6)
          .attr('y', -10)
          .attr('width', 34)
          .attr('height', 20)
          .attr('rx', 3)
          .attr('fill', tagColor)
          .attr('opacity', 0.25);

        g.append('text')
          .attr('x', -boxWidth / 2 + 23)
          .attr('y', 4)
          .attr('text-anchor', 'middle')
          .attr('fill', tagColor)
          .attr('font-size', '9.5px')
          .attr('font-family', 'monospace')
          .attr('font-weight', 'bold')
          .text(methodTag.slice(0, 4));

        // Endpoint Path Label
        g.append('text')
          .attr('x', -boxWidth / 2 + 46)
          .attr('y', 4)
          .attr('fill', '#E0F2FE')
          .attr('font-size', '10px')
          .attr('font-family', 'monospace')
          .attr('font-weight', '600')
          .text(() => {
            const txt = d.label;
            return txt.length > 14 ? txt.slice(0, 13) + '…' : txt;
          });
      } else if (d.type === 'CONSUMER') {
        // Consumer Function Box
        const boxWidth = 145;
        const boxHeight = 36;
        g.append('rect')
          .attr('x', -boxWidth / 2)
          .attr('y', -boxHeight / 2)
          .attr('width', boxWidth)
          .attr('height', boxHeight)
          .attr('rx', 6)
          .attr('fill', isSelected ? '#2A1F0A' : '#12110D')
          .attr('stroke', isSelected ? '#F59E0B' : d.tainted ? '#FF3E00' : '#2F2618')
          .attr('stroke-width', isSelected || d.tainted ? 2 : 1.2);

        // Icon Pill for Function f(x)
        g.append('rect')
          .attr('x', -boxWidth / 2 + 6)
          .attr('y', -10)
          .attr('width', 22)
          .attr('height', 20)
          .attr('rx', 3)
          .attr('fill', d.tainted ? '#EF4444' : '#F59E0B')
          .attr('opacity', 0.2);

        g.append('text')
          .attr('x', -boxWidth / 2 + 17)
          .attr('y', 4)
          .attr('text-anchor', 'middle')
          .attr('fill', d.tainted ? '#F87171' : '#FBBF24')
          .attr('font-size', '9px')
          .attr('font-family', 'monospace')
          .attr('font-weight', 'bold')
          .text('f(x)');

        // Function Name
        g.append('text')
          .attr('x', -boxWidth / 2 + 35)
          .attr('y', 4)
          .attr('fill', '#FEF3C7')
          .attr('font-size', '10px')
          .attr('font-family', 'monospace')
          .attr('font-weight', '600')
          .text(() => {
            const txt = d.label;
            return txt.length > 16 ? txt.slice(0, 15) + '…' : txt;
          });
      } else {
        // SINK NODE (Threat/Warning Hexagon or Box)
        const boxWidth = 135;
        const boxHeight = 38;
        g.append('rect')
          .attr('x', -boxWidth / 2)
          .attr('y', -boxHeight / 2)
          .attr('width', boxWidth)
          .attr('height', boxHeight)
          .attr('rx', 6)
          .attr('fill', isSelected ? '#330800' : '#1A0806')
          .attr('stroke', '#FF3E00')
          .attr('stroke-width', isSelected ? 2.5 : 1.8)
          .attr('filter', d.tainted ? 'url(#glow-critical)' : 'none');

        // Warning Icon Background
        g.append('circle')
          .attr('cx', -boxWidth / 2 + 16)
          .attr('cy', 0)
          .attr('r', 9)
          .attr('fill', '#FF3E00')
          .attr('opacity', 0.25);

        g.append('text')
          .attr('x', -boxWidth / 2 + 16)
          .attr('y', 3.5)
          .attr('text-anchor', 'middle')
          .attr('fill', '#FF5722')
          .attr('font-size', '10px')
          .attr('font-weight', 'bold')
          .text('⚠');

        // Sink Name Label
        g.append('text')
          .attr('x', -boxWidth / 2 + 32)
          .attr('y', -2)
          .attr('fill', '#FF8A65')
          .attr('font-size', '10.5px')
          .attr('font-family', 'monospace')
          .attr('font-weight', '700')
          .text(d.sinkType || d.label);

        // Taint Status / Severity Tag
        g.append('text')
          .attr('x', -boxWidth / 2 + 32)
          .attr('y', 11)
          .attr('fill', d.tainted ? '#FF3E00' : '#F59E0B')
          .attr('font-size', '8.5px')
          .attr('font-family', 'monospace')
          .attr('font-weight', 'bold')
          .text(d.tainted ? 'TAINT EXPLOITABLE' : 'POTENTIAL SINK');
      }

      // Selection ring indicator
      if (isSelected) {
        g.append('rect')
          .attr('x', -75)
          .attr('y', -24)
          .attr('width', 150)
          .attr('height', 48)
          .attr('rx', 10)
          .attr('fill', 'none')
          .attr('stroke', '#FFFFFF')
          .attr('stroke-width', 1.5)
          .attr('stroke-dasharray', '4 3')
          .attr('opacity', 0.75);
      }
    });

    // Tick update loop
    simulation.on('tick', () => {
      // Draw curved bezier links for clean flow
      linkPaths.attr('d', d => {
        const sourceX = (d.source as DataFlowNode).x || 0;
        const sourceY = (d.source as DataFlowNode).y || 0;
        const targetX = (d.target as DataFlowNode).x || 0;
        const targetY = (d.target as DataFlowNode).y || 0;

        if (layoutMode === 'PIPELINE') {
          const dx = targetX - sourceX;
          const curvature = 0.5;
          const cx1 = sourceX + dx * curvature;
          const cy1 = sourceY;
          const cx2 = targetX - dx * curvature;
          const cy2 = targetY;
          return `M${sourceX},${sourceY} C${cx1},${cy1} ${cx2},${cy2} ${targetX},${targetY}`;
        }

        return `M${sourceX},${sourceY} L${targetX},${targetY}`;
      });

      nodeG.attr('transform', d => `translate(${d.x || 0},${d.y || 0})`);
    });

    // Reset zoom on layout change
    svg.on('click', () => setSelectedNode(null));

    return () => {
      simulation.stop();
    };
  }, [filteredNodes, filteredLinks, layoutMode, selectedNode, selectedPathIds]);

  // Zoom control helpers
  const handleZoomIn = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 1.3);
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(250).call(zoomBehaviorRef.current.scaleBy, 0.7);
    }
  };

  const handleResetZoom = () => {
    if (svgRef.current && zoomBehaviorRef.current) {
      d3.select(svgRef.current).transition().duration(350).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleExportJson = () => {
    const json = JSON.stringify(safeGraph, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'secscan-dataflow-taint-matrix.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportSvg = () => {
    if (!svgRef.current) return;
    const serializer = new XMLSerializer();
    const source = serializer.serializeToString(svgRef.current);
    const blob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'secscan-dataflow-graph.svg';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className={`space-y-4 font-sans ${
        isFullscreen ? 'fixed inset-0 z-50 bg-[#060606] p-4 overflow-hidden flex flex-col' : ''
      }`}
    >
      {/* Top Banner & Threat Overview */}
      <div className="bg-[#0A0A0A] p-5 sm:p-6 border border-[#222] rounded-xl flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10.5px] font-mono font-bold bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 tracking-wider uppercase">
              <Network className="w-3.5 h-3.5 text-[#FF3E00]" />
              D3 Data Flow & Taint Analysis
            </span>
            <span className="text-[11px] font-mono text-zinc-400">
              Mapeamento de Fluxo: Endpoints ➔ Handlers ➔ Sinks Perigosos
            </span>
          </div>
          <p className="text-xs text-zinc-300 max-w-3xl leading-relaxed">
            Correlaciona endpoints HTTP detectados pelo <strong>JS-Miner</strong> com funções de consumo e rastreia o
            fluxo de dados não-sanitizados até <strong>sinks perigosos (DOM XSS, eval, cleartext storage)</strong>.
          </p>
        </div>

        {/* Quick Metrics Badges */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="px-3 py-1.5 rounded-lg bg-[#141414] border border-[#262626] text-center min-w-[85px]">
            <span className="block text-[10px] font-mono uppercase text-zinc-400">Endpoints</span>
            <span className="text-sm font-mono font-bold text-[#00E5FF]">
              {safeGraph.metrics.totalEndpoints}
            </span>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-[#141414] border border-[#262626] text-center min-w-[85px]">
            <span className="block text-[10px] font-mono uppercase text-zinc-400">Handlers</span>
            <span className="text-sm font-mono font-bold text-[#F59E0B]">
              {safeGraph.metrics.totalConsumers}
            </span>
          </div>

          <div className="px-3 py-1.5 rounded-lg bg-[#141414] border border-[#262626] text-center min-w-[85px]">
            <span className="block text-[10px] font-mono uppercase text-zinc-400">Sinks</span>
            <span className="text-sm font-mono font-bold text-rose-400">
              {safeGraph.metrics.totalSinks}
            </span>
          </div>

          <div className={`px-3 py-1.5 rounded-lg border text-center min-w-[100px] ${
            safeGraph.metrics.totalTaintFlows > 0
              ? 'bg-rose-950/30 border-rose-600/50 text-rose-300'
              : 'bg-emerald-950/30 border-emerald-600/50 text-emerald-300'
          }`}>
            <span className="block text-[10px] font-mono uppercase font-bold">Caminhos Taint</span>
            <span className="text-sm font-mono font-bold flex items-center justify-center gap-1">
              <Flame className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
              {safeGraph.metrics.totalTaintFlows}
            </span>
          </div>
        </div>
      </div>

      {/* Interactive Controls & Filters Toolbar */}
      <div className="bg-[#0D0D0D] p-3 border border-[#222] rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        {/* Left: Search & Node Type Filter */}
        <div className="flex flex-wrap items-center gap-2 flex-1 min-w-[280px]">
          <div className="relative flex-1 max-w-xs">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              placeholder="Buscar endpoint, função ou sink..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full bg-[#161616] border border-[#2B2B2B] rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-zinc-500 focus:outline-none focus:border-[#FF3E00]"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-white"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Node Category Selector */}
          <div className="flex items-center gap-1 bg-[#161616] p-0.5 rounded-lg border border-[#2B2B2B]">
            {(['ALL', 'ENDPOINT', 'CONSUMER', 'SINK'] as const).map(t => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2 py-1 rounded text-[11px] font-mono font-medium transition-all ${
                  filterType === t
                    ? 'bg-[#262626] text-white shadow-sm font-bold'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                {t === 'ALL' ? 'Todos' : t === 'ENDPOINT' ? 'Endpoints' : t === 'CONSUMER' ? 'Handlers' : 'Sinks'}
              </button>
            ))}
          </div>

          {/* Tainted Flows Only Toggle */}
          <button
            onClick={() => setOnlyTainted(prev => !prev)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-mono transition-all cursor-pointer ${
              onlyTainted
                ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 font-bold'
                : 'bg-[#161616] text-zinc-400 border-[#2B2B2B] hover:text-white'
            }`}
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Apenas Fluxos Críticos (Tainted)</span>
          </button>
        </div>

        {/* Right: Layout Mode Selector & Export Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Layout Mode */}
          <div className="flex items-center gap-1 bg-[#161616] p-0.5 rounded-lg border border-[#2B2B2B]">
            <button
              onClick={() => setLayoutMode('PIPELINE')}
              className={`px-2 py-1 rounded text-[11px] font-mono transition-all ${
                layoutMode === 'PIPELINE' ? 'bg-[#262626] text-[#00E5FF] font-bold' : 'text-zinc-400 hover:text-white'
              }`}
              title="Pipeline Colunar: Endpoints ➔ Handlers ➔ Sinks"
            >
              Pipeline
            </button>
            <button
              onClick={() => setLayoutMode('FORCE')}
              className={`px-2 py-1 rounded text-[11px] font-mono transition-all ${
                layoutMode === 'FORCE' ? 'bg-[#262626] text-[#00E5FF] font-bold' : 'text-zinc-400 hover:text-white'
              }`}
              title="Layout de Força Orgânico D3"
            >
              Orgânico
            </button>
            <button
              onClick={() => setLayoutMode('FILE_GROUPS')}
              className={`px-2 py-1 rounded text-[11px] font-mono transition-all ${
                layoutMode === 'FILE_GROUPS' ? 'bg-[#262626] text-[#00E5FF] font-bold' : 'text-zinc-400 hover:text-white'
              }`}
              title="Agrupado por Arquivos de Origem"
            >
              Arquivos
            </button>
          </div>

          {/* Zoom Buttons */}
          <div className="flex items-center bg-[#161616] border border-[#2B2B2B] rounded-lg">
            <button
              onClick={handleZoomIn}
              className="p-1.5 text-zinc-400 hover:text-white border-r border-[#2B2B2B]"
              title="Aumentar Zoom"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1.5 text-zinc-400 hover:text-white border-r border-[#2B2B2B]"
              title="Diminuir Zoom"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleResetZoom}
              className="p-1.5 text-zinc-400 hover:text-white"
              title="Resetar Enquadramento"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Export & Fullscreen */}
          <button
            onClick={handleExportSvg}
            className="p-1.5 bg-[#161616] hover:bg-[#222] border border-[#2B2B2B] rounded-lg text-zinc-300 hover:text-white"
            title="Exportar Imagem SVG do Grafo"
          >
            <Download className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => setIsFullscreen(prev => !prev)}
            className="p-1.5 bg-[#161616] hover:bg-[#222] border border-[#2B2B2B] rounded-lg text-zinc-300 hover:text-white"
            title={isFullscreen ? 'Sair da Tela Cheia' : 'Tela Cheia'}
          >
            {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Main Graph Canvas & Inspector Split Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 min-h-[580px]">
        {/* Canvas Section */}
        <div
          ref={containerRef}
          className={`relative bg-[#050505] border border-[#222] rounded-xl overflow-hidden ${
            selectedNode ? 'lg:col-span-8' : 'lg:col-span-12'
          } flex flex-col`}
          style={{ minHeight: '580px' }}
        >
          {/* Interactive D3 SVG Canvas */}
          <svg ref={svgRef} className="w-full h-full flex-1 block" />

          {/* Canvas Floating Legend */}
          <div className="absolute bottom-3 left-3 bg-[#0A0A0A]/90 backdrop-blur border border-[#262626] rounded-lg px-3 py-2 text-[10.5px] font-mono flex flex-wrap items-center gap-3 text-zinc-400 pointer-events-none">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-[#00E5FF]" />
              <span>Endpoint API</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-[#F59E0B]" />
              <span>Consumer Function</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded bg-[#FF3E00] animate-pulse" />
              <span>Sink Perigoso</span>
            </span>
            <span className="flex items-center gap-1.5 text-rose-400 font-bold">
              <span className="w-4 border-t-2 border-dashed border-[#FF3E00]" />
              <span>Taint Flow (Crítico)</span>
            </span>
          </div>

          {/* Selected Node Hint */}
          <div className="absolute top-3 right-3 bg-[#0A0A0A]/85 backdrop-blur border border-[#262626] rounded-lg px-3 py-1.5 text-[10px] font-mono text-zinc-400">
            {selectedNode ? (
              <span className="text-[#00E5FF] font-semibold">
                Nó Selecionado: {selectedNode.label} (clique fora para desmarcar)
              </span>
            ) : (
              <span>Clique em qualquer nó para rastrear o fluxo e inspecionar remediação</span>
            )}
          </div>
        </div>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="lg:col-span-4 bg-[#0A0A0A] border border-[#222] rounded-xl p-4 sm:p-5 flex flex-col space-y-4 max-h-[750px] overflow-y-auto">
            {/* Inspector Header */}
            <div className="flex items-start justify-between gap-2 border-b border-[#1E1E1E] pb-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                      selectedNode.type === 'ENDPOINT'
                        ? 'bg-[#00E5FF]/20 text-[#00E5FF] border border-[#00E5FF]/40'
                        : selectedNode.type === 'CONSUMER'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    }`}
                  >
                    {selectedNode.type}
                  </span>

                  {selectedNode.tainted && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-600/30 text-rose-200 border border-rose-500/50 flex items-center gap-1">
                      <Flame className="w-3 h-3 text-rose-400" />
                      TAINT FLOW
                    </span>
                  )}
                </div>
                <h3 className="text-sm font-bold text-white font-mono break-all">{selectedNode.label}</h3>
              </div>

              <button
                onClick={() => setSelectedNode(null)}
                className="p-1 rounded-md text-zinc-400 hover:text-white hover:bg-[#1A1A1A] transition-colors"
                title="Fechar Detalhes"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* File & Line Info */}
            <div className="bg-[#121212] p-3 rounded-lg border border-[#222] space-y-1.5 text-xs font-mono">
              <div className="flex items-center justify-between text-zinc-400">
                <span className="flex items-center gap-1 text-[11px]">
                  <FileCode className="w-3.5 h-3.5 text-zinc-500" />
                  Arquivo:
                </span>
                <span className="text-white font-semibold truncate max-w-[200px]" title={selectedNode.file}>
                  {selectedNode.file}
                </span>
              </div>
              <div className="flex items-center justify-between text-zinc-400">
                <span className="text-[11px]">Linha de Código:</span>
                <span className="text-[#00E5FF] font-bold">Linha {selectedNode.line}</span>
              </div>
              {selectedNode.sublabel && (
                <div className="flex items-center justify-between text-zinc-400">
                  <span className="text-[11px]">Contexto / Escopo:</span>
                  <span className="text-zinc-200">{selectedNode.sublabel}</span>
                </div>
              )}
            </div>

            {/* Threat & CWE Classification (if Sink or Tainted) */}
            {selectedNode.riskCategory && (
              <div className="bg-rose-950/20 border border-rose-800/40 p-3 rounded-lg space-y-2">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                  <span className="text-xs font-bold text-rose-300 font-mono">
                    {selectedNode.riskCategory}
                  </span>
                </div>
                {selectedNode.cwe && (
                  <div className="inline-block px-1.5 py-0.5 rounded bg-rose-900/40 border border-rose-700/50 text-[10px] font-mono text-rose-200">
                    {selectedNode.cwe.id} — {selectedNode.cwe.name}
                  </div>
                )}
                {selectedNode.description && (
                  <p className="text-[11.5px] text-rose-200/90 leading-relaxed">
                    {selectedNode.description}
                  </p>
                )}
              </div>
            )}

            {/* Code Snippet */}
            {selectedNode.snippet && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400">
                  <span className="flex items-center gap-1 font-bold">
                    <Code2 className="w-3.5 h-3.5 text-zinc-500" />
                    Snippet no Código:
                  </span>
                  <button
                    onClick={() => handleCopy(selectedNode.snippet!)}
                    className="inline-flex items-center gap-1 text-[10px] text-zinc-400 hover:text-white"
                  >
                    {copiedText === selectedNode.snippet ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                    <span>{copiedText === selectedNode.snippet ? 'Copiado' : 'Copiar'}</span>
                  </button>
                </div>
                <div className="p-3 bg-black rounded-lg border border-[#222] font-mono text-xs text-zinc-200 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {selectedNode.snippet}
                </div>
              </div>
            )}

            {/* Remediation Guide */}
            {selectedNode.remediation && (
              <div className="space-y-1.5">
                <span className="text-[11px] font-mono font-bold text-emerald-400 flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  Guia de Remediação Recomendado:
                </span>
                <div className="p-3 bg-emerald-950/20 border border-emerald-800/40 rounded-lg text-xs font-mono text-emerald-200 leading-relaxed whitespace-pre-wrap">
                  {selectedNode.remediation}
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="pt-2 flex flex-col gap-2">
              {onSelectFile && (
                <button
                  onClick={() => onSelectFile(selectedNode.file, selectedNode.line)}
                  className="w-full inline-flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-[#161616] hover:bg-[#222] text-white font-mono text-xs font-semibold border border-[#333] transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5 text-[#00E5FF]" />
                  <span>Inspecionar no Code Viewer</span>
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* CSS Animation Keyframes for Tainted Path Motion */}
      <style>{`
        @keyframes dash {
          to {
            stroke-dashoffset: -20;
          }
        }
      `}</style>
    </div>
  );
};
