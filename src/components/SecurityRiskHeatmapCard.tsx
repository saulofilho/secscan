import React, { useState, useMemo, useRef, useEffect } from 'react';
import * as d3 from 'd3';
import {
  FolderTree,
  Flame,
  ShieldAlert,
  Sliders,
  Search,
  Maximize2,
  Minimize2,
  FileCode2,
  ArrowUpRight,
  Sparkles,
  Info,
  Grid,
  Layers,
  ChevronRight,
  CheckCircle2,
  RotateCcw,
  Copy,
  Check,
  Zap,
  Target,
  BarChart2
} from 'lucide-react';
import { ScanFinding, SeverityLevel, ScanReport } from '../types';

export interface SecurityRiskHeatmapCardProps {
  findings: ScanFinding[];
  report?: ScanReport;
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToFile?: (filePath: string) => void;
  onNavigateToScanner?: () => void;
}

export type HeatmapMetricMode = 'DENSITY' | 'RISK_SCORE';
export type HeatmapD3Layout = 'TREEMAP' | 'MATRIX';
export type SeverityFilter = 'ALL' | 'CRITICAL_HIGH' | 'CRITICAL_ONLY';

export interface DirectoryNodeData {
  path: string;
  name: string;
  depth: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  riskScore: number;
  uniqueFilesCount: number;
  files: string[];
  findingsList: ScanFinding[];
  dominantCategory: string;
  densityTier: 'CRITICAL_HOTSPOT' | 'HIGH_DENSITY' | 'MEDIUM_DENSITY' | 'LOW_DENSITY';
  color: string;
}

interface D3HierarchyNode {
  name: string;
  path: string;
  children?: D3HierarchyNode[];
  data?: DirectoryNodeData;
  value?: number;
}

const SEVERITY_WEIGHTS: Record<SeverityLevel, number> = {
  CRITICAL: 25,
  HIGH: 15,
  MEDIUM: 8,
  LOW: 3,
  INFO: 1
};

/**
 * Extracts a normalized directory path from a file path.
 * e.g., "src/components/DashboardOverview.tsx" -> "src/components"
 * ".env" -> "(root)"
 */
function extractDirectory(filePath: string): string {
  if (!filePath) return '(root)';
  const normalized = filePath.replace(/\\/g, '/');
  const lastSlashIndex = normalized.lastIndexOf('/');
  if (lastSlashIndex === -1) {
    return '(root)';
  }
  return normalized.substring(0, lastSlashIndex) || '(root)';
}

export const SecurityRiskHeatmapCard: React.FC<SecurityRiskHeatmapCardProps> = ({
  findings = [],
  report,
  onSelectFinding,
  onNavigateToFile,
  onNavigateToScanner
}) => {
  const [metricMode, setMetricMode] = useState<HeatmapMetricMode>('DENSITY');
  const [d3Layout, setD3Layout] = useState<HeatmapD3Layout>('TREEMAP');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDirectory, setSelectedDirectory] = useState<DirectoryNodeData | null>(null);
  const [hoveredNode, setHoveredNode] = useState<DirectoryNodeData | null>(null);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  // Responsive SVG canvas refs and dimensions
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 440 });

  // Filter findings according to severity threshold
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter === 'CRITICAL_ONLY') {
        return f.severity === 'CRITICAL';
      }
      if (severityFilter === 'CRITICAL_HIGH') {
        return f.severity === 'CRITICAL' || f.severity === 'HIGH';
      }
      return true;
    });
  }, [findings, severityFilter]);

  // Aggregate findings by directory
  const directoryData = useMemo(() => {
    const dirMap = new Map<string, {
      path: string;
      findings: ScanFinding[];
      fileSet: Set<string>;
      categoryCounts: Record<string, number>;
    }>();

    filteredFindings.forEach((f) => {
      const dir = extractDirectory(f.file);
      if (!dirMap.has(dir)) {
        dirMap.set(dir, {
          path: dir,
          findings: [],
          fileSet: new Set(),
          categoryCounts: {}
        });
      }
      const entry = dirMap.get(dir)!;
      entry.findings.push(f);
      entry.fileSet.add(f.file);
      entry.categoryCounts[f.category] = (entry.categoryCounts[f.category] || 0) + 1;
    });

    const result: DirectoryNodeData[] = [];

    dirMap.forEach((entry, path) => {
      let critical = 0;
      let high = 0;
      let medium = 0;
      let low = 0;
      let riskScore = 0;

      entry.findings.forEach((f) => {
        if (f.severity === 'CRITICAL') critical++;
        else if (f.severity === 'HIGH') high++;
        else if (f.severity === 'MEDIUM') medium++;
        else low++;

        riskScore += SEVERITY_WEIGHTS[f.severity] || 3;
      });

      // Determine dominant category
      let dominantCategory = 'Vulnerabilidade Geral';
      let maxCatCount = 0;
      Object.entries(entry.categoryCounts).forEach(([cat, count]) => {
        if (count > maxCatCount) {
          maxCatCount = count;
          dominantCategory = cat;
        }
      });

      // Determine density tier
      let densityTier: DirectoryNodeData['densityTier'] = 'LOW_DENSITY';
      let color = '#22c55e'; // Green for low

      if (critical >= 2 || riskScore >= 100) {
        densityTier = 'CRITICAL_HOTSPOT';
        color = '#ef4444'; // Red for critical hotspot
      } else if (critical >= 1 || high >= 3 || riskScore >= 50) {
        densityTier = 'HIGH_DENSITY';
        color = '#f97316'; // Orange for high
      } else if (high >= 1 || medium >= 3 || riskScore >= 20) {
        densityTier = 'MEDIUM_DENSITY';
        color = '#eab308'; // Amber for medium
      } else {
        densityTier = 'LOW_DENSITY';
        color = '#3b82f6'; // Blue for low
      }

      const pathParts = path.split('/');
      const displayName = pathParts[pathParts.length - 1] || path;

      result.push({
        path,
        name: displayName,
        depth: path === '(root)' ? 0 : pathParts.length,
        totalFindings: entry.findings.length,
        criticalCount: critical,
        highCount: high,
        mediumCount: medium,
        lowCount: low,
        riskScore,
        uniqueFilesCount: entry.fileSet.size,
        files: Array.from(entry.fileSet),
        findingsList: entry.findings,
        dominantCategory,
        densityTier,
        color
      });
    });

    // Sort by risk score descending
    return result.sort((a, b) => b.riskScore - a.riskScore);
  }, [filteredFindings]);

  // Filter directories by search query
  const displayDirectories = useMemo(() => {
    if (!searchQuery.trim()) return directoryData;
    const q = searchQuery.toLowerCase().trim();
    return directoryData.filter(
      (d) =>
        d.path.toLowerCase().includes(q) ||
        d.name.toLowerCase().includes(q) ||
        d.files.some((f) => f.toLowerCase().includes(q))
    );
  }, [directoryData, searchQuery]);

  // Overall heatmap statistics
  const heatmapStats = useMemo(() => {
    const totalDirs = directoryData.length;
    const totalVulnerabilities = directoryData.reduce((acc, d) => acc + d.totalFindings, 0);
    const criticalHotspots = directoryData.filter((d) => d.densityTier === 'CRITICAL_HOTSPOT').length;
    const topDirectory = directoryData[0] || null;
    const avgPerDir = totalDirs > 0 ? (totalVulnerabilities / totalDirs).toFixed(1) : '0';

    return {
      totalDirs,
      totalVulnerabilities,
      criticalHotspots,
      topDirectory,
      avgPerDir
    };
  }, [directoryData]);

  // ResizeObserver on canvas container
  useEffect(() => {
    if (!containerRef.current) return;

    const observer = new ResizeObserver((entries) => {
      if (!entries || entries.length === 0) return;
      const { width } = entries[0].contentRect;
      if (width > 0) {
        // Adjust height proportionally: minimum 360, max 520
        const calculatedHeight = Math.max(360, Math.min(520, Math.round(width * 0.52)));
        setDimensions({ width, height: calculatedHeight });
      }
    });

    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // D3 Rendering effect
  useEffect(() => {
    if (!svgRef.current || displayDirectories.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const { width, height } = dimensions;

    if (d3Layout === 'TREEMAP') {
      // Build D3 Hierarchy Tree for squarified treemap
      const rootData: D3HierarchyNode = {
        name: 'root',
        path: 'root',
        children: displayDirectories.map((dir) => ({
          name: dir.name,
          path: dir.path,
          data: dir,
          value: metricMode === 'DENSITY' ? dir.totalFindings : dir.riskScore
        }))
      };

      const hierarchyRoot = d3
        .hierarchy(rootData)
        .sum((d) => d.value || 0)
        .sort((a, b) => (b.value || 0) - (a.value || 0));

      const treemapLayout = d3
        .treemap<D3HierarchyNode>()
        .size([width, height])
        .paddingInner(3)
        .paddingOuter(2)
        .round(true)
        .tile(d3.treemapSquarify.ratio(1));

      treemapLayout(hierarchyRoot);

      // Color scale based on density and risk
      const maxVal = d3.max(displayDirectories, (d) =>
        metricMode === 'DENSITY' ? d.totalFindings : d.riskScore
      ) || 10;

      const colorScale = d3
        .scaleSequentialLog<string>()
        .domain([1, Math.max(2, maxVal)])
        .interpolator(d3.interpolateReds);

      // Render group container
      const g = svg.append('g').attr('class', 'd3-treemap-group');

      const nodes = hierarchyRoot.leaves();

      const cell = g
        .selectAll('g.d3-cell')
        .data(nodes)
        .enter()
        .append('g')
        .attr('class', 'd3-cell cursor-pointer')
        .attr('transform', (d: any) => `translate(${d.x0},${d.y0})`)
        .on('mouseenter', (event, d: any) => {
          if (d.data?.data) {
            setHoveredNode(d.data.data);
          }
          d3.select(event.currentTarget)
            .select('rect')
            .transition()
            .duration(150)
            .attr('stroke', '#FFFFFF')
            .attr('stroke-width', 2)
            .attr('filter', 'brightness(1.15)');
        })
        .on('mouseleave', (event, d: any) => {
          setHoveredNode(null);
          const isSelected = selectedDirectory?.path === d.data?.data?.path;
          d3.select(event.currentTarget)
            .select('rect')
            .transition()
            .duration(150)
            .attr('stroke', isSelected ? '#00FF66' : '#262626')
            .attr('stroke-width', isSelected ? 2 : 1)
            .attr('filter', 'none');
        })
        .on('click', (_, d: any) => {
          if (d.data?.data) {
            setSelectedDirectory((prev) =>
              prev?.path === d.data.data.path ? null : d.data.data
            );
          }
        });

      // Background Rectangles
      cell
        .append('rect')
        .attr('width', (d: any) => Math.max(0, d.x1 - d.x0))
        .attr('height', (d: any) => Math.max(0, d.y1 - d.y0))
        .attr('rx', 4)
        .attr('ry', 4)
        .attr('fill', (d: any) => {
          const dir = d.data?.data as DirectoryNodeData | undefined;
          if (!dir) return '#1A1A1A';
          if (dir.criticalCount > 0) {
            // Intense warning red for critical
            return d3.interpolateRgb('#3B0700', '#991B1B')(Math.min(1, dir.criticalCount / 3));
          }
          if (dir.highCount > 0) {
            return d3.interpolateRgb('#2E1300', '#C2410C')(Math.min(1, dir.highCount / 4));
          }
          if (dir.mediumCount > 0) {
            return d3.interpolateRgb('#261E01', '#A16207')(Math.min(1, dir.mediumCount / 4));
          }
          return '#0B2014'; // Low density green-tint
        })
        .attr('stroke', (d: any) => {
          const isSelected = selectedDirectory?.path === d.data?.data?.path;
          return isSelected ? '#00FF66' : '#262626';
        })
        .attr('stroke-width', (d: any) => {
          const isSelected = selectedDirectory?.path === d.data?.data?.path;
          return isSelected ? 2 : 1;
        })
        .attr('opacity', 0.95);

      // Directory Title Label
      cell
        .each(function (d: any) {
          const w = d.x1 - d.x0;
          const h = d.y1 - d.y0;
          const dir = d.data?.data as DirectoryNodeData | undefined;
          if (!dir || w < 40 || h < 26) return;

          const group = d3.select(this);

          // Path / Name Text
          const textGroup = group
            .append('text')
            .attr('x', 7)
            .attr('y', 16)
            .attr('fill', '#FFFFFF')
            .attr('font-size', w > 120 ? '11px' : '9.5px')
            .attr('font-family', 'ui-monospace, monospace')
            .attr('font-weight', '700')
            .attr('pointer-events', 'none');

          // Truncate path if box is small
          const maxChars = Math.max(4, Math.floor(w / 7.5));
          const textStr = dir.path.length > maxChars ? dir.name : dir.path;
          textGroup.text(textStr.length > maxChars ? textStr.substring(0, maxChars - 1) + '…' : textStr);

          // Second row: Metric value and badges if room permits
          if (h >= 46 && w >= 60) {
            const valGroup = group
              .append('text')
              .attr('x', 7)
              .attr('y', 34)
              .attr('fill', dir.criticalCount > 0 ? '#FF3E00' : '#FF7A00')
              .attr('font-size', '12px')
              .attr('font-family', 'ui-monospace, monospace')
              .attr('font-weight', '900')
              .attr('pointer-events', 'none');

            const labelVal =
              metricMode === 'DENSITY'
                ? `${dir.totalFindings} achados`
                : `${dir.riskScore} pts`;
            valGroup.text(labelVal);
          }

          // Top-right pill for critical count
          if (dir.criticalCount > 0 && w >= 90 && h >= 32) {
            const badgeG = group
              .append('g')
              .attr('transform', `translate(${w - 38}, 6)`)
              .attr('pointer-events', 'none');

            badgeG
              .append('rect')
              .attr('width', 32)
              .attr('height', 14)
              .attr('rx', 2)
              .attr('fill', '#FF3E00')
              .attr('opacity', 0.9);

            badgeG
              .append('text')
              .attr('x', 16)
              .attr('y', 10.5)
              .attr('fill', '#FFFFFF')
              .attr('font-size', '8.5px')
              .attr('font-family', 'ui-monospace, monospace')
              .attr('font-weight', '900')
              .attr('text-anchor', 'middle')
              .text(`${dir.criticalCount} CRIT`);
          }
        });
    } else {
      // D3 MATRIX VIEW: Directories on Y-Axis vs Severity Columns on X-Axis
      const margin = { top: 28, right: 20, bottom: 20, left: 160 };
      const matrixWidth = width - margin.left - margin.right;
      const matrixHeight = height - margin.top - margin.bottom;

      const topDirs = displayDirectories.slice(0, 10);
      const severityTiers: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

      const yScale = d3
        .scaleBand()
        .domain(topDirs.map((d) => d.path))
        .range([0, matrixHeight])
        .padding(0.12);

      const xScale = d3
        .scaleBand()
        .domain(severityTiers)
        .range([0, matrixWidth])
        .padding(0.08);

      const g = svg
        .append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

      // X Axis labels
      g.selectAll('.x-label')
        .data(severityTiers)
        .enter()
        .append('text')
        .attr('class', 'x-label')
        .attr('x', (d) => (xScale(d) || 0) + xScale.bandwidth() / 2)
        .attr('y', -10)
        .attr('text-anchor', 'middle')
        .attr('fill', (d) => {
          if (d === 'CRITICAL') return '#FF3E00';
          if (d === 'HIGH') return '#FF7A00';
          if (d === 'MEDIUM') return '#EAB308';
          return '#3366FF';
        })
        .attr('font-family', 'ui-monospace, monospace')
        .attr('font-size', '10px')
        .attr('font-weight', '900')
        .text((d) => d);

      // Y Axis labels (Directory Paths)
      g.selectAll('.y-label')
        .data(topDirs)
        .enter()
        .append('text')
        .attr('class', 'y-label cursor-pointer')
        .attr('x', -8)
        .attr('y', (d) => (yScale(d.path) || 0) + yScale.bandwidth() / 2 + 3)
        .attr('text-anchor', 'end')
        .attr('fill', (d) => (selectedDirectory?.path === d.path ? '#00FF66' : '#AAAAAA'))
        .attr('font-family', 'ui-monospace, monospace')
        .attr('font-size', '10px')
        .attr('font-weight', '600')
        .text((d) => (d.path.length > 22 ? d.path.substring(0, 20) + '…' : d.path))
        .on('click', (_, d) => {
          setSelectedDirectory((prev) => (prev?.path === d.path ? null : d));
        });

      // Matrix Heatmap Cells
      topDirs.forEach((dir) => {
        severityTiers.forEach((sev) => {
          let count = 0;
          if (sev === 'CRITICAL') count = dir.criticalCount;
          else if (sev === 'HIGH') count = dir.highCount;
          else if (sev === 'MEDIUM') count = dir.mediumCount;
          else count = dir.lowCount;

          const cellX = xScale(sev) || 0;
          const cellY = yScale(dir.path) || 0;
          const cellW = xScale.bandwidth();
          const cellH = yScale.bandwidth();

          const cellG = g
            .append('g')
            .attr('class', 'matrix-cell cursor-pointer')
            .on('mouseenter', () => setHoveredNode(dir))
            .on('mouseleave', () => setHoveredNode(null))
            .on('click', () => {
              setSelectedDirectory((prev) => (prev?.path === dir.path ? null : dir));
            });

          // Cell Rect
          cellG
            .append('rect')
            .attr('x', cellX)
            .attr('y', cellY)
            .attr('width', cellW)
            .attr('height', cellH)
            .attr('rx', 3)
            .attr('fill', () => {
              if (count === 0) return '#0D0D0D';
              if (sev === 'CRITICAL') return d3.interpolateRgb('#3B0700', '#FF3E00')(Math.min(1, count / 3));
              if (sev === 'HIGH') return d3.interpolateRgb('#2E1300', '#FF7A00')(Math.min(1, count / 4));
              if (sev === 'MEDIUM') return d3.interpolateRgb('#261E01', '#EAB308')(Math.min(1, count / 4));
              return d3.interpolateRgb('#05112E', '#3366FF')(Math.min(1, count / 4));
            })
            .attr('stroke', count > 0 ? '#333' : '#1A1A1A')
            .attr('stroke-width', 1);

          // Cell text
          if (count > 0) {
            cellG
              .append('text')
              .attr('x', cellX + cellW / 2)
              .attr('y', cellY + cellH / 2 + 3.5)
              .attr('text-anchor', 'middle')
              .attr('fill', '#FFFFFF')
              .attr('font-size', '11px')
              .attr('font-family', 'ui-monospace, monospace')
              .attr('font-weight', 'bold')
              .text(count);
          }
        });
      });
    }
  }, [displayDirectories, d3Layout, metricMode, dimensions, selectedDirectory]);

  // Handle path copying
  const handleCopyPath = (path: string) => {
    navigator.clipboard.writeText(path);
    setCopiedPath(path);
    setTimeout(() => setCopiedPath(null), 2000);
  };

  return (
    <div
      id="security-risk-heatmap-card"
      className="bg-[#080808] border border-[#222] p-4 sm:p-6 space-y-6 w-full min-w-0 overflow-hidden"
    >
      {/* Card Header & Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-[#222] min-w-0">
        <div className="space-y-1.5 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#00FF66] bg-[#00FF66]/10 px-2.5 py-0.5 border border-[#00FF66]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <FolderTree className="w-3.5 h-3.5" />
              D3.JS VISUALIZATION // REPOSITORY DIRECTORY DENSITY MATRIX
            </span>
            <span className="text-[10px] font-mono bg-[#111] text-[#AAA] border border-[#262626] px-2 py-0.5 font-bold">
              {heatmapStats.totalDirs} DIRETÓRIOS
            </span>
            {heatmapStats.criticalHotspots > 0 && (
              <span className="text-[10px] font-mono bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/30 px-2 py-0.5 font-bold flex items-center gap-1">
                <Flame className="w-3 h-3" />
                {heatmapStats.criticalHotspots} HOTSPOTS CRÍTICOS
              </span>
            )}
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Security Risk Heatmap</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Mapeamento dinâmico baseado em <strong>D3.js</strong> da densidade e carga de vulnerabilidades por diretórios e submódulos do repositório. Identifique a concentração espacial de ameaças para direcionar a remediação arquitetural.
          </p>
        </div>

        {/* Global Action & Scanner Jump */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {onNavigateToScanner && (
            <button
              onClick={onNavigateToScanner}
              className="px-4 py-2.5 bg-[#161616] hover:bg-[#FF3E00] hover:text-white border border-[#333] hover:border-[#FF3E00] text-white font-mono text-xs uppercase tracking-wider flex items-center gap-2 transition-all cursor-pointer shadow-sm"
              title="Abrir Scanner com todos os achados"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
              <span>Ver no Scanner ({findings.length})</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Highlights Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#0D0D0D] border border-[#222] p-3 flex flex-col justify-between min-w-0">
          <div className="text-[10px] font-mono text-[#777] uppercase flex items-center justify-between">
            <span>Diretórios Afetados</span>
            <FolderTree className="w-3.5 h-3.5 text-[#00FF66]" />
          </div>
          <div className="text-2xl font-black font-mono text-white mt-1">
            {heatmapStats.totalDirs}
          </div>
          <div className="text-[9px] font-mono text-[#666] truncate mt-0.5">
            {heatmapStats.totalVulnerabilities} vulnerabilidades totais
          </div>
        </div>

        <div className="bg-[#0D0D0D] border border-[#222] p-3 flex flex-col justify-between min-w-0">
          <div className="text-[10px] font-mono text-[#777] uppercase flex items-center justify-between">
            <span>Hotspot Principal</span>
            <Flame className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="text-sm font-black font-mono text-[#FF3E00] mt-1 truncate">
            {heatmapStats.topDirectory ? heatmapStats.topDirectory.path : 'Nenhum'}
          </div>
          <div className="text-[9px] font-mono text-[#888] truncate mt-0.5">
            {heatmapStats.topDirectory
              ? `${heatmapStats.topDirectory.totalFindings} achados (${heatmapStats.topDirectory.criticalCount} críticos)`
              : 'Sem anomalias'}
          </div>
        </div>

        <div className="bg-[#0D0D0D] border border-[#222] p-3 flex flex-col justify-between min-w-0">
          <div className="text-[10px] font-mono text-[#777] uppercase flex items-center justify-between">
            <span>Densidade Média</span>
            <Target className="w-3.5 h-3.5 text-[#FF7A00]" />
          </div>
          <div className="text-2xl font-black font-mono text-[#FF7A00] mt-1">
            {heatmapStats.avgPerDir}
          </div>
          <div className="text-[9px] font-mono text-[#666] mt-0.5">
            falhas / diretório afetado
          </div>
        </div>

        <div className="bg-[#0D0D0D] border border-[#222] p-3 flex flex-col justify-between min-w-0">
          <div className="text-[10px] font-mono text-[#777] uppercase flex items-center justify-between">
            <span>Hotspots Críticos</span>
            <Zap className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="text-2xl font-black font-mono text-white mt-1">
            {heatmapStats.criticalHotspots}
          </div>
          <div className="text-[9px] font-mono text-[#FF3E00] mt-0.5">
            ação imediata requerida
          </div>
        </div>
      </div>

      {/* Interactive Toolbars: Metric Sizing, D3 Layout, Filter & Search */}
      <div className="bg-[#0D0D0D] border border-[#1E1E1E] p-3 sm:p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 min-w-0">
        <div className="flex flex-wrap items-center gap-3 min-w-0">
          {/* D3 Layout Mode */}
          <div className="flex items-center bg-[#141414] border border-[#262626] p-0.5">
            <button
              onClick={() => setD3Layout('TREEMAP')}
              className={`px-3 py-1.5 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                d3Layout === 'TREEMAP'
                  ? 'bg-[#00FF66] text-black shadow-sm font-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <Grid className="w-3 h-3" />
              <span>D3 Treemap (Área)</span>
            </button>
            <button
              onClick={() => setD3Layout('MATRIX')}
              className={`px-3 py-1.5 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
                d3Layout === 'MATRIX'
                  ? 'bg-[#00FF66] text-black shadow-sm font-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              <Layers className="w-3 h-3" />
              <span>D3 Matriz de Severidade</span>
            </button>
          </div>

          {/* Metric Sizing (Count vs Risk Score) */}
          <div className="flex items-center bg-[#141414] border border-[#262626] p-0.5">
            <button
              onClick={() => setMetricMode('DENSITY')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer ${
                metricMode === 'DENSITY'
                  ? 'bg-white text-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              Volume (Achados)
            </button>
            <button
              onClick={() => setMetricMode('RISK_SCORE')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer ${
                metricMode === 'RISK_SCORE'
                  ? 'bg-white text-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              Carga de Risco (Pts)
            </button>
          </div>

          {/* Severity filter */}
          <div className="flex items-center bg-[#141414] border border-[#262626] p-0.5">
            <button
              onClick={() => setSeverityFilter('ALL')}
              className={`px-2 py-1 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer ${
                severityFilter === 'ALL'
                  ? 'bg-[#262626] text-white'
                  : 'text-[#777] hover:text-white'
              }`}
            >
              Todos
            </button>
            <button
              onClick={() => setSeverityFilter('CRITICAL_HIGH')}
              className={`px-2 py-1 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer ${
                severityFilter === 'CRITICAL_HIGH'
                  ? 'bg-[#FF7A00] text-black font-black'
                  : 'text-[#777] hover:text-white'
              }`}
            >
              Crítico + Alto
            </button>
            <button
              onClick={() => setSeverityFilter('CRITICAL_ONLY')}
              className={`px-2 py-1 text-[10px] font-mono uppercase font-bold transition-all cursor-pointer ${
                severityFilter === 'CRITICAL_ONLY'
                  ? 'bg-[#FF3E00] text-white font-black'
                  : 'text-[#777] hover:text-white'
              }`}
            >
              Apenas Crítico
            </button>
          </div>
        </div>

        {/* Directory Search */}
        <div className="relative min-w-[200px] sm:w-64">
          <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filtrar por diretório..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#141414] border border-[#2A2A2A] focus:border-[#00FF66] text-xs font-mono text-white pl-8 pr-3 py-1.5 outline-none transition-colors"
          />
        </div>
      </div>

      {/* Main Canvas + Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start min-w-0">
        {/* Left Column: Interactive D3 Canvas */}
        <div className="lg:col-span-8 bg-[#0B0B0B] border border-[#222] p-3 sm:p-4 flex flex-col space-y-3 min-w-0 overflow-hidden">
          <div className="flex items-center justify-between text-[11px] font-mono text-[#888] pb-2 border-b border-[#1A1A1A]">
            <span className="flex items-center gap-1.5 text-white">
              <span className="w-2 h-2 rounded-full bg-[#00FF66]" />
              {d3Layout === 'TREEMAP'
                ? 'D3 Treemap: O tamanho dos blocos reflete a densidade proporcional do diretório'
                : 'D3 Matriz: Densidade de vulnerabilidades cruzada por severidade'}
            </span>
            <span className="text-[10px] text-[#666] hidden sm:inline">
              Clique em um bloco para inspecionar
            </span>
          </div>

          {/* D3 Canvas Container */}
          <div
            ref={containerRef}
            className="w-full relative min-h-[360px] flex items-center justify-center bg-[#050505] border border-[#1C1C1C] rounded overflow-hidden"
          >
            {displayDirectories.length > 0 ? (
              <svg
                ref={svgRef}
                width={dimensions.width}
                height={dimensions.height}
                className="w-full h-auto block"
                viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
              />
            ) : (
              <div className="text-center text-[#666] font-mono text-xs py-16">
                <CheckCircle2 className="w-8 h-8 text-[#00FF41] mx-auto mb-2 opacity-80" />
                <span className="font-bold text-white block">NENHUM DIRETÓRIO ENCONTRADO</span>
                <span className="text-[10px] text-[#666]">
                  Nenhum diretório corresponde aos filtros selecionados.
                </span>
              </div>
            )}

            {/* Hover Floating HUD Tooltip */}
            {hoveredNode && (
              <div className="absolute top-3 right-3 pointer-events-none bg-[#0D0D0D]/95 border border-[#333] shadow-2xl p-3 font-mono text-xs space-y-1.5 max-w-xs z-30 backdrop-blur-sm animate-in fade-in duration-100">
                <div className="flex items-center justify-between gap-2 border-b border-[#222] pb-1">
                  <span className="text-white font-bold truncate">{hoveredNode.path}</span>
                  <span
                    className="text-[9px] font-bold px-1.5 py-0.5 rounded-none"
                    style={{
                      backgroundColor: `${hoveredNode.color}20`,
                      color: hoveredNode.color,
                      border: `1px solid ${hoveredNode.color}50`
                    }}
                  >
                    {hoveredNode.densityTier.replace('_', ' ')}
                  </span>
                </div>
                <div className="flex items-center justify-between text-[#AAA]">
                  <span>Vulnerabilidades:</span>
                  <span className="font-bold text-white">{hoveredNode.totalFindings} achados</span>
                </div>
                <div className="flex items-center justify-between text-[#AAA]">
                  <span>Carga de Risco:</span>
                  <span className="font-bold text-[#FF7A00]">{hoveredNode.riskScore} pts</span>
                </div>
                <div className="flex items-center justify-between text-[#AAA]">
                  <span>Arquivos Afetados:</span>
                  <span className="font-bold text-white">{hoveredNode.uniqueFilesCount} arquivos</span>
                </div>
                <div className="flex items-center gap-1.5 pt-1 text-[9.5px]">
                  <span className="px-1.5 py-0.5 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40">
                    {hoveredNode.criticalCount} Crit
                  </span>
                  <span className="px-1.5 py-0.5 bg-[#FF7A00]/20 text-[#FF7A00] border border-[#FF7A00]/40">
                    {hoveredNode.highCount} Alto
                  </span>
                  <span className="px-1.5 py-0.5 bg-[#EAB308]/20 text-[#EAB308] border border-[#EAB308]/40">
                    {hoveredNode.mediumCount} Méd
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Color Scale Legend */}
          <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-[#777] pt-2 border-t border-[#1C1C1C]">
            <div className="flex items-center gap-2">
              <span>Intensidade de Risco:</span>
              <div className="flex items-center gap-1">
                <span className="w-3 h-3 bg-[#0B2014] border border-[#00FF41]/40" title="Baixa densidade" />
                <span className="w-3 h-3 bg-[#261E01] border border-[#EAB308]/40" title="Média densidade" />
                <span className="w-3 h-3 bg-[#2E1300] border border-[#FF7A00]/40" title="Alta densidade" />
                <span className="w-3 h-3 bg-[#3B0700] border border-[#FF3E00]/40" title="Hotspot Crítico" />
              </div>
              <span className="text-[#999]">Seguro &rarr; Crítico</span>
            </div>

            <div className="flex items-center gap-3">
              <span>{displayDirectories.length} diretórios mapeados</span>
              {selectedDirectory && (
                <button
                  onClick={() => setSelectedDirectory(null)}
                  className="text-[#FF3E00] hover:underline uppercase font-bold"
                >
                  Limpar Seleção [{selectedDirectory.name}]
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Directory Inspector & Hotspot Drilldown */}
        <div className="lg:col-span-4 bg-[#0D0D0D] border border-[#222] p-4 sm:p-5 flex flex-col space-y-4 min-w-0">
          <div className="flex items-center justify-between pb-3 border-b border-[#222]">
            <div className="flex items-center gap-2 min-w-0">
              <FolderTree className="w-4 h-4 text-[#00FF66] shrink-0" />
              <h3 className="text-xs font-mono font-black uppercase text-white tracking-wider truncate">
                {selectedDirectory ? `Diretório: ${selectedDirectory.name}` : 'Inspeção de Diretório'}
              </h3>
            </div>
            {selectedDirectory && (
              <button
                onClick={() => handleCopyPath(selectedDirectory.path)}
                className="p-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white transition-colors"
                title="Copiar caminho completo do diretório"
              >
                {copiedPath === selectedDirectory.path ? (
                  <Check className="w-3 h-3 text-[#00FF66]" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
              </button>
            )}
          </div>

          {selectedDirectory ? (
            <div className="space-y-4 font-mono">
              {/* Directory Path Banner */}
              <div className="p-2.5 bg-[#050505] border border-[#222] text-[11px] text-[#00FF66] font-bold break-all">
                {selectedDirectory.path}
              </div>

              {/* Stats Grid */}
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 bg-[#080808] border border-[#1C1C1C]">
                  <div className="text-[9px] text-[#777] uppercase">Vulnerabilidades</div>
                  <div className="text-xl font-black text-white mt-0.5">
                    {selectedDirectory.totalFindings}
                  </div>
                  <div className="text-[9px] text-[#FF3E00]">
                    {selectedDirectory.criticalCount} críticas
                  </div>
                </div>

                <div className="p-2.5 bg-[#080808] border border-[#1C1C1C]">
                  <div className="text-[9px] text-[#777] uppercase">Carga de Risco</div>
                  <div className="text-xl font-black text-[#FF7A00] mt-0.5">
                    {selectedDirectory.riskScore}
                    <span className="text-xs text-[#666]"> pts</span>
                  </div>
                  <div className="text-[9px] text-[#AAA]">
                    {selectedDirectory.uniqueFilesCount} arquivo(s)
                  </div>
                </div>
              </div>

              {/* Severity Breakdown Bar */}
              <div className="space-y-1.5">
                <div className="text-[10px] text-[#888] uppercase font-bold">Composição por Severidade</div>
                <div className="grid grid-cols-4 gap-1 text-center text-[10px]">
                  <div className="p-1 bg-[#FF3E00]/15 border border-[#FF3E00]/30 text-[#FF3E00]">
                    <span className="block font-bold">{selectedDirectory.criticalCount}</span>
                    <span className="text-[8px] uppercase">Crit</span>
                  </div>
                  <div className="p-1 bg-[#FF7A00]/15 border border-[#FF7A00]/30 text-[#FF7A00]">
                    <span className="block font-bold">{selectedDirectory.highCount}</span>
                    <span className="text-[8px] uppercase">Alto</span>
                  </div>
                  <div className="p-1 bg-[#EAB308]/15 border border-[#EAB308]/30 text-[#EAB308]">
                    <span className="block font-bold">{selectedDirectory.mediumCount}</span>
                    <span className="text-[8px] uppercase">Méd</span>
                  </div>
                  <div className="p-1 bg-[#3366FF]/15 border border-[#3366FF]/30 text-[#3366FF]">
                    <span className="block font-bold">{selectedDirectory.lowCount}</span>
                    <span className="text-[8px] uppercase">Baixo</span>
                  </div>
                </div>
              </div>

              {/* Affected Files List */}
              <div className="space-y-2">
                <div className="text-[10px] text-[#888] uppercase font-bold flex items-center justify-between">
                  <span>Arquivos Afetados ({selectedDirectory.files.length})</span>
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                  {selectedDirectory.files.map((file) => {
                    const fileFindings = selectedDirectory.findingsList.filter((f) => f.file === file);
                    const hasCrit = fileFindings.some((f) => f.severity === 'CRITICAL');

                    return (
                      <div
                        key={file}
                        onClick={() => onNavigateToFile?.(file)}
                        className="p-2 bg-[#080808] border border-[#1E1E1E] hover:border-[#333] transition-all flex items-center justify-between cursor-pointer group text-xs"
                      >
                        <div className="flex items-center gap-1.5 min-w-0 truncate">
                          <FileCode2 className={`w-3.5 h-3.5 shrink-0 ${hasCrit ? 'text-[#FF3E00]' : 'text-[#888]'}`} />
                          <span className="text-zinc-300 group-hover:text-white truncate text-[11px]">
                            {file.replace(selectedDirectory.path + '/', '')}
                          </span>
                        </div>
                        <span className="text-[10px] font-bold px-1.5 py-0.5 bg-[#141414] text-[#AAA] border border-[#222] shrink-0 ml-2">
                          {fileFindings.length} falhas
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Top Finding Snippet from this directory */}
              {selectedDirectory.findingsList.length > 0 && (
                <div className="space-y-1.5 pt-2 border-t border-[#1C1C1C]">
                  <div className="text-[10px] text-[#888] uppercase font-bold">
                    Vulnerabilidade Crítica em Destaque
                  </div>
                  <div
                    onClick={() => onSelectFinding?.(selectedDirectory.findingsList[0])}
                    className="p-2.5 bg-[#050505] border border-[#222] hover:border-[#FF3E00] cursor-pointer transition-all text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between text-[#888] text-[9.5px]">
                      <span className="text-white font-bold truncate max-w-[180px]">
                        {selectedDirectory.findingsList[0].ruleName}
                      </span>
                      <span className="text-[#FF3E00] flex items-center gap-0.5">
                        Linha {selectedDirectory.findingsList[0].line} &rarr;
                      </span>
                    </div>
                    <div className="text-[#FF7A00] truncate bg-[#000] p-1 border border-[#181818] text-[10.5px]">
                      {selectedDirectory.findingsList[0].maskedSecret || selectedDirectory.findingsList[0].snippet}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="text-center text-[#666] font-mono text-xs py-10 space-y-2">
              <FolderTree className="w-8 h-8 text-[#444] mx-auto opacity-70" />
              <span className="font-bold text-zinc-400 block uppercase">Nenhum Diretório Selecionado</span>
              <p className="text-[10px] text-[#666] leading-relaxed">
                Passe o cursor sobre os blocos no mapa D3 ou clique em qualquer diretório para inspecionar os arquivos afetados, contagem de severidade e atalhos de remediação.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
