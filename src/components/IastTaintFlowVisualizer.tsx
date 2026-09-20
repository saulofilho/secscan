import React, { useState, useEffect, useRef, useMemo } from 'react';
import * as d3 from 'd3';
import {
  Activity,
  Play,
  Pause,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Terminal,
  Globe,
  Database,
  FileCode,
  Layers,
  ArrowRight,
  Code2,
  Zap,
  Info,
  Bug,
  CheckCircle2,
  Check,
  Copy,
  Sliders,
  ChevronRight,
  Eye,
  Crosshair
} from 'lucide-react';
import {
  IastVulnerabilityFinding,
  IastTraceStep,
  IastHookSensor,
  IastHookCategory
} from '../types/iast';

interface IastTaintFlowVisualizerProps {
  finding: IastVulnerabilityFinding;
  allHooks?: IastHookSensor[];
  onSelectFile?: (filePath: string, line?: number) => void;
}

interface VisualNode {
  id: string;
  stepIndex: number;
  label: string;
  sublabel: string;
  file: string;
  line: number;
  type: 'SOURCE' | 'PROPAGATION' | 'SANITIZER' | 'SINK';
  hookCategory: IastHookCategory;
  hookId: string;
  variableName: string;
  runtimeValue: string;
  isTainted: boolean;
  sanitizationApplied?: string;
  description: string;
  // d3 coordinates
  x?: number;
  y?: number;
}

interface VisualEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  tainted: boolean;
  sanitized: boolean;
}

export const IastTaintFlowVisualizer: React.FC<IastTaintFlowVisualizerProps> = ({
  finding,
  allHooks,
  onSelectFile
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  
  const [selectedStepIndex, setSelectedStepIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(true);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1800); // ms per step
  const [activePlaybackIndex, setActivePlaybackIndex] = useState<number>(0);
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  const [copiedPayload, setCopiedPayload] = useState<boolean>(false);
  const [viewMode, setViewMode] = useState<'INTERACTIVE_CANVAS' | 'SWIMLANE'>('INTERACTIVE_CANVAS');

  // Convert finding tracePath to structured visual nodes and edges
  const { nodes, edges } = useMemo(() => {
    const traceSteps = finding.tracePath;
    const visualNodes: VisualNode[] = [];
    const visualEdges: VisualEdge[] = [];

    traceSteps.forEach((step, idx) => {
      let nodeType: VisualNode['type'] = 'PROPAGATION';
      if (idx === 0) {
        nodeType = 'SOURCE';
      } else if (idx === traceSteps.length - 1) {
        nodeType = 'SINK';
      } else if (step.sanitizationApplied) {
        nodeType = 'SANITIZER';
      }

      const nodeId = `step-${step.stepIndex}`;
      visualNodes.push({
        id: nodeId,
        stepIndex: step.stepIndex,
        label: step.functionName,
        sublabel: `${step.file}:${step.line}`,
        file: step.file,
        line: step.line,
        type: nodeType,
        hookCategory: step.hookCategory,
        hookId: step.hookId,
        variableName: step.variableName,
        runtimeValue: step.runtimeValue,
        isTainted: step.isTainted,
        sanitizationApplied: step.sanitizationApplied,
        description: step.description
      });

      if (idx > 0) {
        const prevNodeId = `step-${traceSteps[idx - 1].stepIndex}`;
        visualEdges.push({
          id: `edge-${prevNodeId}-${nodeId}`,
          source: prevNodeId,
          target: nodeId,
          label: step.variableName,
          tainted: step.isTainted,
          sanitized: !!step.sanitizationApplied
        });
      }
    });

    return { nodes: visualNodes, edges: visualEdges };
  }, [finding]);

  const activeStep = nodes[selectedStepIndex] || nodes[0];

  // Auto-play animation through trace steps
  useEffect(() => {
    if (!isPlaying || nodes.length <= 1) return;

    const interval = setInterval(() => {
      setActivePlaybackIndex(prev => {
        const next = (prev + 1) % nodes.length;
        setSelectedStepIndex(next);
        return next;
      });
    }, playbackSpeed);

    return () => clearInterval(interval);
  }, [isPlaying, nodes.length, playbackSpeed]);

  // Render D3 SVG graph
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || nodes.length === 0) return;

    const width = containerRef.current.clientWidth || 800;
    const height = 340;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Defs for gradients, glow filters and markers
    const defs = svg.append('defs');

    // Arrowhead marker - Tainted (Pink/Rose)
    defs.append('marker')
      .attr('id', 'taint-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#f43f5e');

    // Arrowhead marker - Active Animated (Cyan)
    defs.append('marker')
      .attr('id', 'active-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#06b6d4');

    // Glow filter
    const filter = defs.append('filter')
      .attr('id', 'taint-glow')
      .attr('x', '-30%')
      .attr('y', '-30%')
      .attr('width', '160%')
      .attr('height', '160%');
    filter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    const g = svg.append('g').attr('class', 'main-flow-group');

    // Zoom setup
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.6, 2.2])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setZoomLevel(event.transform.k);
      });

    svg.call(zoom);

    // Calculate node horizontal layout
    const marginX = 90;
    const availableWidth = width - marginX * 2;
    const stepX = nodes.length > 1 ? availableWidth / (nodes.length - 1) : availableWidth / 2;
    const centerY = height / 2;

    const positionedNodes = nodes.map((node, i) => ({
      ...node,
      x: marginX + i * stepX,
      y: centerY + (i % 2 === 1 ? (nodes.length > 3 ? (i % 4 === 1 ? -30 : 30) : 0) : 0)
    }));

    // Background Lane Guides
    const guideGroup = g.append('g').attr('class', 'lane-guides');
    positionedNodes.forEach((node, i) => {
      // Stage Pillar
      guideGroup.append('line')
        .attr('x1', node.x)
        .attr('y1', 25)
        .attr('x2', node.x)
        .attr('y2', height - 25)
        .attr('stroke', '#222')
        .attr('stroke-dasharray', '3 3')
        .attr('stroke-width', 1);

      guideGroup.append('text')
        .attr('x', node.x)
        .attr('y', 20)
        .attr('text-anchor', 'middle')
        .attr('fill', node.type === 'SOURCE' ? '#38bdf8' : node.type === 'SINK' ? '#f43f5e' : '#a855f7')
        .attr('font-size', '10px')
        .attr('font-family', 'monospace')
        .attr('font-weight', 'bold')
        .text(`ETAPA 0${node.stepIndex} [${node.type}]`);
    });

    // Draw Edges (Curves with dataflow animations)
    const edgeGroup = g.append('g').attr('class', 'edges');

    positionedNodes.forEach((targetNode, idx) => {
      if (idx === 0) return;
      const sourceNode = positionedNodes[idx - 1];
      const isEdgeActive = idx <= selectedStepIndex;

      // Cubic curve path
      const dx = targetNode.x - sourceNode.x;
      const pathD = `M ${sourceNode.x} ${sourceNode.y} C ${sourceNode.x + dx * 0.5} ${sourceNode.y}, ${targetNode.x - dx * 0.5} ${targetNode.y}, ${targetNode.x} ${targetNode.y}`;

      // Outer glow/shadow line
      edgeGroup.append('path')
        .attr('d', pathD)
        .attr('fill', 'none')
        .attr('stroke', isEdgeActive ? '#f43f5e' : '#333')
        .attr('stroke-width', isEdgeActive ? 4 : 2)
        .attr('stroke-opacity', isEdgeActive ? 0.35 : 0.4)
        .attr('filter', isEdgeActive ? 'url(#taint-glow)' : 'none');

      // Main connection line
      const mainPath = edgeGroup.append('path')
        .attr('d', pathD)
        .attr('fill', 'none')
        .attr('stroke', isEdgeActive ? '#f43f5e' : '#444')
        .attr('stroke-width', isEdgeActive ? 2.5 : 1.5)
        .attr('stroke-dasharray', isEdgeActive ? '6 4' : 'none')
        .attr('marker-end', isEdgeActive ? 'url(#taint-arrow)' : 'none');

      // Animate dash offset for active tainted propagation
      if (isEdgeActive) {
        mainPath.append('animate')
          .attr('attributeName', 'stroke-dashoffset')
          .attr('from', '20')
          .attr('to', '0')
          .attr('dur', '1.2s')
          .attr('repeatCount', 'indefinite');
      }

      // Edge Label: Parameter/Variable Name
      const midX = (sourceNode.x + targetNode.x) / 2;
      const midY = (sourceNode.y + targetNode.y) / 2 - 14;

      const labelBadge = edgeGroup.append('g')
        .attr('transform', `translate(${midX}, ${midY})`);

      labelBadge.append('rect')
        .attr('x', -50)
        .attr('y', -10)
        .attr('width', 100)
        .attr('height', 18)
        .attr('rx', 4)
        .attr('fill', '#000000e0')
        .attr('stroke', isEdgeActive ? '#f43f5e55' : '#333')
        .attr('stroke-width', 1);

      labelBadge.append('text')
        .attr('x', 0)
        .attr('y', 2)
        .attr('text-anchor', 'middle')
        .attr('fill', isEdgeActive ? '#fda4af' : '#888')
        .attr('font-size', '9px')
        .attr('font-family', 'monospace')
        .attr('font-weight', 'bold')
        .text(targetNode.variableName.length > 14 ? targetNode.variableName.slice(0, 12) + '…' : targetNode.variableName);
    });

    // Draw Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');

    positionedNodes.forEach((node, idx) => {
      const isSelected = idx === selectedStepIndex;
      const isReached = idx <= selectedStepIndex;

      const nodeG = nodeGroup.append('g')
        .attr('transform', `translate(${node.x}, ${node.y})`)
        .attr('class', 'interactive-node')
        .style('cursor', 'pointer')
        .on('click', () => {
          setSelectedStepIndex(idx);
          setIsPlaying(false);
        });

      // Pulse ring for selected node
      if (isSelected) {
        nodeG.append('circle')
          .attr('r', 34)
          .attr('fill', 'none')
          .attr('stroke', node.type === 'SINK' ? '#f43f5e' : node.type === 'SOURCE' ? '#38bdf8' : '#a855f7')
          .attr('stroke-width', 2)
          .attr('opacity', 0.8)
          .append('animate')
          .attr('attributeName', 'r')
          .attr('from', '26')
          .attr('to', '42')
          .attr('dur', '1.5s')
          .attr('repeatCount', 'indefinite');

        nodeG.append('circle')
          .attr('r', 34)
          .attr('fill', 'none')
          .attr('stroke', node.type === 'SINK' ? '#f43f5e' : node.type === 'SOURCE' ? '#38bdf8' : '#a855f7')
          .attr('stroke-width', 1.5)
          .attr('opacity', 0.8)
          .append('animate')
          .attr('attributeName', 'opacity')
          .attr('from', '0.8')
          .attr('to', '0')
          .attr('dur', '1.5s')
          .attr('repeatCount', 'indefinite');
      }

      // Main Outer Circle
      nodeG.append('circle')
        .attr('r', isSelected ? 26 : 22)
        .attr('fill', isReached 
          ? (node.type === 'SOURCE' ? '#082f49' : node.type === 'SINK' ? '#4c0519' : '#3b0764') 
          : '#111')
        .attr('stroke', isReached
          ? (node.type === 'SOURCE' ? '#38bdf8' : node.type === 'SINK' ? '#f43f5e' : '#c084fc')
          : '#444')
        .attr('stroke-width', isSelected ? 3 : 2)
        .attr('filter', isReached && node.isTainted ? 'url(#taint-glow)' : 'none');

      // Step Number in center
      nodeG.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '4')
        .attr('fill', isReached ? '#fff' : '#666')
        .attr('font-size', isSelected ? '13px' : '11px')
        .attr('font-family', 'monospace')
        .attr('font-weight', 'bold')
        .text(node.stepIndex);

      // Node Label (Function Name)
      const labelY = idx % 2 === 1 && nodes.length > 3 ? (node.y > centerY ? 45 : -40) : 42;

      nodeG.append('text')
        .attr('x', 0)
        .attr('y', labelY)
        .attr('text-anchor', 'middle')
        .attr('fill', isSelected ? '#fff' : '#cbd5e1')
        .attr('font-size', '11px')
        .attr('font-weight', 'bold')
        .attr('font-family', 'monospace')
        .text(node.label.length > 20 ? node.label.slice(0, 18) + '…' : node.label);

      // Node Sublabel (File:Line)
      nodeG.append('text')
        .attr('x', 0)
        .attr('y', labelY + 14)
        .attr('text-anchor', 'middle')
        .attr('fill', '#94a3b8')
        .attr('font-size', '9.5px')
        .attr('font-family', 'monospace')
        .text(node.sublabel.length > 24 ? '…' + node.sublabel.slice(-22) : node.sublabel);

      // Taint Badge pill above node
      if (node.isTainted && isReached) {
        const badgeY = labelY > 0 ? -36 : 42;
        const badge = nodeG.append('g').attr('transform', `translate(0, ${badgeY})`);
        badge.append('rect')
          .attr('x', -26)
          .attr('y', -8)
          .attr('width', 52)
          .attr('height', 16)
          .attr('rx', 8)
          .attr('fill', '#f43f5e25')
          .attr('stroke', '#f43f5e88')
          .attr('stroke-width', 1);

        badge.append('text')
          .attr('text-anchor', 'middle')
          .attr('dy', '3')
          .attr('fill', '#fda4af')
          .attr('font-size', '8.5px')
          .attr('font-family', 'monospace')
          .attr('font-weight', 'bold')
          .text('TAINTED');
      }
    });

  }, [nodes, selectedStepIndex, finding]);

  const handleResetZoom = () => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(400).call(
      d3.zoom<SVGSVGElement, unknown>().transform as any,
      d3.zoomIdentity
    );
    setZoomLevel(1);
  };

  const handleZoom = (delta: number) => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    svg.transition().duration(300).call(
      d3.zoom<SVGSVGElement, unknown>().scaleBy as any,
      delta
    );
  };

  const copyPayload = (payload: string) => {
    navigator.clipboard.writeText(payload);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <div className={`p-5 rounded-xl border border-cyan-500/30 bg-black/80 space-y-4 shadow-xl shadow-black/60 transition-all ${
      isFullscreen ? 'fixed inset-4 z-50 overflow-y-auto bg-black border-cyan-500/60' : ''
    }`}>
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-white/10 pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Activity className="w-4 h-4" />
            </span>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              Visualizador Gráfico de Taint Flow (Source &rarr; Sink)
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30">
                IAST Runtime Hooks
              </span>
            </h3>
          </div>
          <p className="text-xs text-white/60">
            Mapeamento dinâmico do vetor de ataque interceptado por sensores em runtime, desde a entrada HTTP até o sink vulnerável.
          </p>
        </div>

        {/* View mode toggle & interactive controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* View mode pill */}
          <div className="flex p-0.5 rounded-lg bg-white/5 border border-white/10 text-[11px] font-mono">
            <button
              onClick={() => setViewMode('INTERACTIVE_CANVAS')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                viewMode === 'INTERACTIVE_CANVAS'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-white/60 hover:text-white'
              }`}
            >
              <Eye className="w-3 h-3" />
              <span>Grafo D3</span>
            </button>
            <button
              onClick={() => setViewMode('SWIMLANE')}
              className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${
                viewMode === 'SWIMLANE'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                  : 'text-white/60 hover:text-white'
              }`}
            >
              <Layers className="w-3 h-3" />
              <span>Swimlane</span>
            </button>
          </div>

          {/* Animation playback */}
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-semibold cursor-pointer transition-colors"
            title={isPlaying ? 'Pausar animação de taint' : 'Reproduzir animação passo a passo'}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3 h-3" />
                <span>Pausar</span>
              </>
            ) : (
              <>
                <Play className="w-3 h-3 fill-current" />
                <span>Animar Fluxo</span>
              </>
            )}
          </button>

          {/* Zoom controls */}
          <div className="flex items-center gap-1 bg-white/5 p-1 rounded-lg border border-white/10">
            <button
              onClick={() => handleZoom(1.2)}
              className="p-1 rounded hover:bg-white/10 text-white/70 hover:text-white cursor-pointer"
              title="Aproximar Zoom"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => handleZoom(0.8)}
              className="p-1 rounded hover:bg-white/10 text-white/70 hover:text-white cursor-pointer"
              title="Afastar Zoom"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleResetZoom}
              className="p-1 rounded hover:bg-white/10 text-white/70 hover:text-white cursor-pointer"
              title="Resetar Zoom"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Fullscreen button */}
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 border border-white/10 text-white/70 hover:text-white cursor-pointer"
            title={isFullscreen ? 'Sair de tela cheia' : 'Visualizar em tela cheia'}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main Visualizer Area */}
      {viewMode === 'INTERACTIVE_CANVAS' ? (
        <div className="relative border border-white/10 rounded-xl bg-gradient-to-b from-[#060b13] to-black overflow-hidden shadow-inner">
          {/* Flow Legend overlay */}
          <div className="absolute top-3 left-3 z-10 flex items-center gap-3 p-2 rounded-lg bg-black/80 border border-white/10 backdrop-blur-sm text-[10px] font-mono">
            <span className="flex items-center gap-1 text-sky-400">
              <span className="w-2 h-2 rounded-full bg-sky-400" />
              Source HTTP
            </span>
            <span className="flex items-center gap-1 text-purple-400">
              <span className="w-2 h-2 rounded-full bg-purple-400" />
              Propagação
            </span>
            <span className="flex items-center gap-1 text-rose-400 font-bold">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
              Sink Perigoso
            </span>
            <span className="text-white/40">|</span>
            <span className="text-white/60">Zoom: {Math.round(zoomLevel * 100)}%</span>
          </div>

          {/* Step Timeline navigator */}
          <div className="absolute top-3 right-3 z-10 flex items-center gap-1 p-1.5 rounded-lg bg-black/80 border border-white/10 backdrop-blur-sm text-[11px] font-mono">
            <span className="text-white/50 px-1">Passo:</span>
            {nodes.map((n, i) => (
              <button
                key={n.id}
                onClick={() => {
                  setSelectedStepIndex(i);
                  setIsPlaying(false);
                }}
                className={`w-6 h-6 rounded flex items-center justify-center font-bold text-xs cursor-pointer transition-all ${
                  i === selectedStepIndex
                    ? 'bg-cyan-500 text-black shadow-md shadow-cyan-500/40'
                    : i < selectedStepIndex
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-white/5 text-white/40 hover:text-white'
                }`}
              >
                {n.stepIndex}
              </button>
            ))}
          </div>

          {/* D3 Canvas Element */}
          <div ref={containerRef} className="w-full h-[340px]">
            <svg ref={svgRef} className="w-full h-full cursor-grab active:cursor-grabbing" />
          </div>

          {/* Bottom active step indicator pill */}
          <div className="p-2.5 bg-black/90 border-t border-white/10 flex flex-wrap items-center justify-between text-xs font-mono gap-2">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-bold">Etapa Ativa #{activeStep.stepIndex}:</span>
              <span className="text-white font-semibold">{activeStep.label}</span>
              <span className="text-white/40">({activeStep.file}:{activeStep.line})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-white/50">Tainted Var:</span>
              <span className="text-rose-300 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-800/40">
                {activeStep.variableName}
              </span>
            </div>
          </div>
        </div>
      ) : (
        /* Swimlane Flow Mode */
        <div className="border border-white/10 rounded-xl bg-black/60 p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Column 1: Source */}
            <div className="p-3.5 rounded-lg border border-sky-500/30 bg-sky-950/15 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-sky-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5" />
                  Origem HTTP (Source)
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-sky-500/20 text-sky-300">
                  {finding.httpMethod}
                </span>
              </div>
              <div className="p-2.5 rounded bg-black/60 border border-white/5 font-mono text-xs text-white/90 space-y-1">
                <div className="text-[10px] text-white/40">Endpoint:</div>
                <div className="text-sky-300 font-bold">{finding.sourceEndpoint}</div>
                <div className="text-[10px] text-white/40 pt-1">Parâmetro Tainted:</div>
                <div className="text-amber-300">{finding.taintedParameter}</div>
              </div>
            </div>

            {/* Column 2: Propagation */}
            <div className="p-3.5 rounded-lg border border-purple-500/30 bg-purple-950/15 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Trilha de Propagação
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300">
                  {nodes.length - 2} etapas intermédias
                </span>
              </div>
              <div className="p-2.5 rounded bg-black/60 border border-white/5 font-mono text-xs text-white/90 space-y-1.5 max-h-36 overflow-y-auto">
                {nodes.slice(1, -1).map((step, idx) => (
                  <div key={idx} className="border-b border-white/5 pb-1.5 last:border-b-0">
                    <div className="text-purple-300 font-semibold">{step.label}</div>
                    <div className="text-[10px] text-white/50">{step.file}:{step.line}</div>
                  </div>
                ))}
                {nodes.length <= 2 && (
                  <div className="text-white/40 text-[11px] italic">
                    Propagação direta do controller para o sink.
                  </div>
                )}
              </div>
            </div>

            {/* Column 3: Dangerous Sink */}
            <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-950/15 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5" />
                  Consumo no Sink (Vulnerabilidade)
                </span>
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 font-bold">
                  {finding.severity}
                </span>
              </div>
              <div className="p-2.5 rounded bg-black/60 border border-white/5 font-mono text-xs text-white/90 space-y-1">
                <div className="text-[10px] text-white/40">Função do Sink Interceptada:</div>
                <div className="text-rose-300 font-bold">{finding.sinkFunction}</div>
                <div className="text-[10px] text-white/40 pt-1">Localização:</div>
                <div className="text-white/70">{finding.sinkFile}:{finding.sinkLine}</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Deep Step Detail Panel for the currently highlighted node */}
      <div className="p-4 rounded-xl border border-white/10 bg-black/50 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-6 h-6 rounded-full bg-cyan-500/20 border border-cyan-400 text-cyan-300 flex items-center justify-center font-mono font-bold text-xs">
              {activeStep.stepIndex}
            </span>
            <h4 className="text-xs font-bold font-mono text-white">
              Detalhes de Execução do Hook: <span className="text-cyan-400">{activeStep.label}</span>
            </h4>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/5 border border-white/10 text-white/60">
              {activeStep.hookCategory}
            </span>
          </div>

          {onSelectFile && (
            <button
              onClick={() => onSelectFile(activeStep.file, activeStep.line)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-white/70 hover:text-white border border-white/10 text-[11px] font-mono transition-colors cursor-pointer"
            >
              <FileCode className="w-3.5 h-3.5 text-cyan-400" />
              <span>Abrir Código ({activeStep.file}:{activeStep.line})</span>
            </button>
          )}
        </div>

        <p className="text-xs text-white/80 leading-relaxed font-sans">
          {activeStep.description}
        </p>

        {/* Runtime Parameter and Payload Inspection */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          <div className="p-3 rounded-lg bg-black/80 border border-white/10 space-y-1.5">
            <div className="flex items-center justify-between text-[10px] font-mono text-white/50">
              <span>Variável Rastreada:</span>
              <span className="text-purple-300">{activeStep.variableName}</span>
            </div>
            <div className="font-mono text-xs text-amber-300 bg-black p-2 rounded border border-white/5 break-all">
              {activeStep.runtimeValue}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-black/80 border border-white/10 space-y-1.5">
            <div className="flex items-center justify-between text-[10px] font-mono text-white/50">
              <span>Sensor Hook ID:</span>
              <span className="text-cyan-300">{activeStep.hookId}</span>
            </div>
            <div className="font-mono text-[11px] text-white/70 bg-black p-2 rounded border border-white/5 flex items-center justify-between gap-2">
              <span className="truncate">Taint Status: <strong className="text-rose-400">CONFIRMED TAINTED</strong></span>
              <button
                onClick={() => copyPayload(activeStep.runtimeValue)}
                className="flex items-center gap-1 text-[10px] text-white/50 hover:text-white px-2 py-0.5 rounded bg-white/5 border border-white/10 cursor-pointer"
                title="Copiar valor do payload em tempo de execução"
              >
                {copiedPayload ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-emerald-300">Copiado</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span>Copiar</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
