import React, { useState, useMemo } from 'react';
import { 
  Flame, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  ExternalLink, 
  FileCode, 
  Search, 
  Copy, 
  Check, 
  SlidersHorizontal, 
  Grid, 
  ListOrdered, 
  BarChart3, 
  Clock, 
  Crosshair, 
  Zap,
  Info,
  X,
  ArrowUpRight,
  Filter
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip as RechartsTooltip, 
  Legend, 
  Cell 
} from 'recharts';
import { ScanFinding } from '../types';

export interface BreachHeatmapProps {
  findings: ScanFinding[];
  onSelectFinding?: (finding: ScanFinding) => void;
  onNavigateToFile?: (filePath: string) => void;
  onNavigateToScanner?: () => void;
}

export type RemediationPriority = 'P0_CRITICAL' | 'P1_HIGH' | 'P2_MODERATE' | 'P3_LOW';

export interface FileBreachSummary {
  file: string;
  fileName: string;
  directory: string;
  extension: string;
  matchCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  distinctRules: string[];
  maxEntropy: number;
  riskIndex: number;
  priority: RemediationPriority;
  priorityLabel: string;
  slaWindow: string;
  thermalIntensity: number; // 0 to 100
  thermalColor: string;
  findings: ScanFinding[];
}

type ViewMode = 'GRID' | 'QUEUE' | 'CHART';
type SortMode = 'FREQUENCY' | 'RISK' | 'PRIORITY' | 'NAME';

export const BreachHeatmap: React.FC<BreachHeatmapProps> = ({
  findings = [],
  onSelectFinding,
  onNavigateToFile,
  onNavigateToScanner
}) => {
  const [viewMode, setViewMode] = useState<ViewMode>('GRID');
  const [sortMode, setSortMode] = useState<SortMode>('FREQUENCY');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFileSummary, setSelectedFileSummary] = useState<FileBreachSummary | null>(null);
  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  // Group findings by file and calculate breach frequency & remediation metrics
  const fileSummaries = useMemo<FileBreachSummary[]>(() => {
    if (!findings || findings.length === 0) return [];

    const fileMap = new Map<string, ScanFinding[]>();

    findings.forEach(finding => {
      const filePath = finding.file || 'unknown';
      if (!fileMap.has(filePath)) {
        fileMap.set(filePath, []);
      }
      fileMap.get(filePath)!.push(finding);
    });

    // Find maximum matches for thermal normalization
    let maxMatchesOverall = 1;
    fileMap.forEach(items => {
      if (items.length > maxMatchesOverall) {
        maxMatchesOverall = items.length;
      }
    });

    const summaries: FileBreachSummary[] = [];

    fileMap.forEach((fileFindings, filePath) => {
      const matchCount = fileFindings.length;
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      let maxEntropy = 0;
      const ruleSet = new Set<string>();

      fileFindings.forEach(f => {
        if (f.severity === 'CRITICAL') criticalCount++;
        else if (f.severity === 'HIGH') highCount++;
        else if (f.severity === 'MEDIUM') mediumCount++;
        else lowCount++;

        if (f.entropy && f.entropy > maxEntropy) {
          maxEntropy = f.entropy;
        }

        if (f.ruleName) {
          ruleSet.add(f.ruleName);
        }
      });

      // Remediation priority & SLA calculation
      let priority: RemediationPriority;
      let priorityLabel: string;
      let slaWindow: string;

      if (criticalCount > 0 || (highCount >= 2 && matchCount >= 3)) {
        priority = 'P0_CRITICAL';
        priorityLabel = 'P0 • Imediato';
        slaWindow = '< 2 Horas';
      } else if (highCount > 0 || matchCount >= 3) {
        priority = 'P1_HIGH';
        priorityLabel = 'P1 • Alta Urgência';
        slaWindow = '< 24 Horas';
      } else if (mediumCount > 0 || matchCount >= 2) {
        priority = 'P2_MODERATE';
        priorityLabel = 'P2 • Moderado';
        slaWindow = '< 48 Horas';
      } else {
        priority = 'P3_LOW';
        priorityLabel = 'P3 • Rotina';
        slaWindow = 'Próxima Sprint';
      }

      // Breach Risk Index (0 - 100+)
      const riskIndex = Math.min(
        100,
        Math.round(criticalCount * 35 + highCount * 20 + mediumCount * 10 + lowCount * 5 + matchCount * 3)
      );

      // Thermal Intensity (0 - 100)
      const thermalIntensity = Math.min(
        100,
        Math.round((matchCount / Math.max(maxMatchesOverall, 1)) * 60 + (riskIndex / 100) * 40)
      );

      // Thermal Color Mapping
      let thermalColor = '#3366FF';
      if (priority === 'P0_CRITICAL' || matchCount >= 5) {
        thermalColor = '#FF3E00'; // Vermelho Térmico Intenso
      } else if (priority === 'P1_HIGH' || matchCount >= 3) {
        thermalColor = '#FF7A00'; // Âmbar Quente
      } else if (priority === 'P2_MODERATE' || matchCount >= 2) {
        thermalColor = '#EAB308'; // Amarelo Alerta
      }

      const parts = filePath.split('/');
      const fileName = parts.pop() || filePath;
      const directory = parts.join('/') || './';
      const extMatch = fileName.match(/\.([a-zA-Z0-9]+)$/);
      const extension = extMatch ? extMatch[1] : 'file';

      summaries.push({
        file: filePath,
        fileName,
        directory,
        extension,
        matchCount,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        distinctRules: Array.from(ruleSet),
        maxEntropy: Number(maxEntropy.toFixed(2)),
        riskIndex,
        priority,
        priorityLabel,
        slaWindow,
        thermalIntensity,
        thermalColor,
        findings: fileFindings
      });
    });

    return summaries;
  }, [findings]);

  // Apply filters and sorting
  const filteredSummaries = useMemo(() => {
    return fileSummaries.filter(item => {
      // Priority filter
      if (priorityFilter !== 'ALL' && item.priority !== priorityFilter) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchFile = item.file.toLowerCase().includes(query);
        const matchRule = item.distinctRules.some(r => r.toLowerCase().includes(query));
        if (!matchFile && !matchRule) return false;
      }

      return true;
    }).sort((a, b) => {
      switch (sortMode) {
        case 'FREQUENCY':
          return b.matchCount - a.matchCount || b.riskIndex - a.riskIndex;
        case 'RISK':
          return b.riskIndex - a.riskIndex || b.matchCount - a.matchCount;
        case 'PRIORITY': {
          const rank = { P0_CRITICAL: 4, P1_HIGH: 3, P2_MODERATE: 2, P3_LOW: 1 };
          return rank[b.priority] - rank[a.priority] || b.matchCount - a.matchCount;
        }
        case 'NAME':
          return a.fileName.localeCompare(b.fileName);
        default:
          return b.matchCount - a.matchCount;
      }
    });
  }, [fileSummaries, priorityFilter, searchQuery, sortMode]);

  // Key KPI metrics
  const stats = useMemo(() => {
    const totalFiles = fileSummaries.length;
    const totalMatches = fileSummaries.reduce((sum, f) => sum + f.matchCount, 0);
    const avgMatches = totalFiles > 0 ? (totalMatches / totalFiles).toFixed(1) : '0';
    const topFile = fileSummaries.slice().sort((a, b) => b.matchCount - a.matchCount)[0] || null;
    const p0Count = fileSummaries.filter(f => f.priority === 'P0_CRITICAL').length;
    const p1Count = fileSummaries.filter(f => f.priority === 'P1_HIGH').length;

    return {
      totalFiles,
      totalMatches,
      avgMatches,
      topFile,
      urgentCount: p0Count + p1Count,
      p0Count,
      p1Count
    };
  }, [fileSummaries]);

  // Chart data for Frequency Distribution view
  const chartData = useMemo(() => {
    return fileSummaries
      .slice()
      .sort((a, b) => b.matchCount - a.matchCount)
      .slice(0, 10)
      .map(item => ({
        name: item.fileName.length > 18 ? item.fileName.slice(0, 15) + '...' : item.fileName,
        fullName: item.file,
        total: item.matchCount,
        critical: item.criticalCount,
        high: item.highCount,
        medium: item.mediumCount,
        low: item.lowCount,
        color: item.thermalColor,
        risk: item.riskIndex
      }));
  }, [fileSummaries]);

  const handleCopyRemediationReport = (item: FileBreachSummary) => {
    const lines: string[] = [];
    lines.push(`=======================================================`);
    lines.push(`BREACH REMEDIATION TICKET: ${item.file}`);
    lines.push(`Priority: ${item.priorityLabel} (SLA: ${item.slaWindow})`);
    lines.push(`Pattern Match Frequency: ${item.matchCount} ocorrências`);
    lines.push(`Risk Score: ${item.riskIndex}/100 • Max Entropy: ${item.maxEntropy}`);
    lines.push(`Distinct Patterns: ${item.distinctRules.join(', ')}`);
    lines.push(`=======================================================\n`);
    lines.push(`IDENTIFIED MATCHES:`);
    item.findings.forEach((f, idx) => {
      lines.push(`[#${idx + 1}] Line ${f.line}: [${f.severity}] ${f.ruleName}`);
      lines.push(`    Masked: ${f.maskedSecret}`);
      lines.push(`    Action: ${f.remediation}`);
    });
    lines.push(`\nRemediation Guidance: Rotate exposed credentials and check git commit history.`);

    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopiedFile(item.file);
      setTimeout(() => setCopiedFile(null), 2000);
    });
  };

  return (
    <section 
      id="breach-heatmap-section"
      className="bg-[#080808] border-2 border-[#262626] p-6 lg:p-8 space-y-6 relative overflow-hidden"
    >
      {/* Subtle Thermal Glow Accent */}
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-[#FF3E00]/5 rounded-full blur-3xl pointer-events-none" />

      {/* Header & Title */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#1F1F1F] relative z-10">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono font-black text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase tracking-widest flex items-center gap-1.5">
              <Flame className="w-3.5 h-3.5 text-[#FF3E00] animate-pulse" />
              BREACH HEATMAP // REMEDIATION PRIORITIZATION
            </span>
            <span className="text-[10px] font-mono text-[#00FF41] bg-[#00FF41]/10 px-2 py-0.5 border border-[#00FF41]/30 font-bold uppercase">
              {stats.totalFiles} ARQUIVOS COMPROMETIDOS
            </span>
            <span className="text-[10px] font-mono text-[#AAA] bg-[#141414] px-2 py-0.5 border border-[#333]">
              {stats.totalMatches} ACHADOS SENSÍVEIS
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Mapa de Calor de Violação & Frequência</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Identifica os arquivos com a maior densidade de padrões sensíveis expostos, correlacionando frequência de ocorrência, severidade e entropia para estabelecer uma fila ordenada de remediação imediata (SLA P0/P1).
          </p>
        </div>

        {/* View Switcher Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="flex items-center bg-[#111] p-1 border border-[#2A2A2A] rounded-xs font-mono text-xs">
            <button
              id="btn-breach-view-grid"
              type="button"
              onClick={() => setViewMode('GRID')}
              className={`flex items-center gap-1.5 px-3 py-1.5 font-bold uppercase transition-all cursor-pointer ${
                viewMode === 'GRID'
                  ? 'bg-[#FF3E00] text-white shadow-[0_0_10px_rgba(255,62,0,0.3)]'
                  : 'text-[#888] hover:text-white hover:bg-white/5'
              }`}
              title="Visualização em Grade de Calor Térmico"
            >
              <Grid className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Grade Térmica</span>
            </button>

            <button
              id="btn-breach-view-queue"
              type="button"
              onClick={() => setViewMode('QUEUE')}
              className={`flex items-center gap-1.5 px-3 py-1.5 font-bold uppercase transition-all cursor-pointer ${
                viewMode === 'QUEUE'
                  ? 'bg-[#FF3E00] text-white shadow-[0_0_10px_rgba(255,62,0,0.3)]'
                  : 'text-[#888] hover:text-white hover:bg-white/5'
              }`}
              title="Fila Ordenada de Remediação Priorizada"
            >
              <ListOrdered className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Fila Priorizada</span>
            </button>

            <button
              id="btn-breach-view-chart"
              type="button"
              onClick={() => setViewMode('CHART')}
              className={`flex items-center gap-1.5 px-3 py-1.5 font-bold uppercase transition-all cursor-pointer ${
                viewMode === 'CHART'
                  ? 'bg-[#FF3E00] text-white shadow-[0_0_10px_rgba(255,62,0,0.3)]'
                  : 'text-[#888] hover:text-white hover:bg-white/5'
              }`}
              title="Gráfico Comparativo de Frequência"
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Top Arquivos</span>
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 font-mono">
        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="w-1 h-full bg-[#FF3E00] absolute left-0 top-0" />
          <div className="flex items-center justify-between text-[#888] text-[10px] uppercase font-bold pl-1">
            <span>Maior Vetor de Violação</span>
            <Crosshair className="w-3.5 h-3.5 text-[#FF3E00]" />
          </div>
          <div className="mt-2 text-white font-black text-sm sm:text-base truncate pl-1" title={stats.topFile?.file || 'Nenhum'}>
            {stats.topFile ? stats.topFile.fileName : 'Nenhum'}
          </div>
          <div className="mt-1 flex items-center justify-between text-[10px] pl-1">
            <span className="text-[#FF3E00] font-bold">
              {stats.topFile ? `${stats.topFile.matchCount} ocorrências` : '0'}
            </span>
            <span className="text-[#666]">{stats.topFile?.directory || '-'}</span>
          </div>
        </div>

        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="w-1 h-full bg-[#FF7A00] absolute left-0 top-0" />
          <div className="flex items-center justify-between text-[#888] text-[10px] uppercase font-bold pl-1">
            <span>Fila de Urgência Imediata</span>
            <ShieldAlert className="w-3.5 h-3.5 text-[#FF7A00]" />
          </div>
          <div className="mt-2 text-3xl font-black text-white pl-1">
            {stats.urgentCount}
          </div>
          <div className="mt-1 flex items-center gap-2 text-[10px] pl-1">
            <span className="text-[#FF3E00] font-bold">{stats.p0Count} P0 Imediatos</span>
            <span className="text-[#777]">•</span>
            <span className="text-[#FF7A00] font-bold">{stats.p1Count} P1 Alta</span>
          </div>
        </div>

        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="w-1 h-full bg-[#EAB308] absolute left-0 top-0" />
          <div className="flex items-center justify-between text-[#888] text-[10px] uppercase font-bold pl-1">
            <span>Média de Padrões / Arquivo</span>
            <Zap className="w-3.5 h-3.5 text-[#EAB308]" />
          </div>
          <div className="mt-2 text-3xl font-black text-white pl-1">
            {stats.avgMatches}
          </div>
          <div className="mt-1 text-[10px] text-[#777] pl-1">
            Taxa de densidade em arquivos afetados
          </div>
        </div>

        <div className="p-4 bg-[#0D0D0D] border border-[#222] relative overflow-hidden">
          <div className="w-1 h-full bg-[#3366FF] absolute left-0 top-0" />
          <div className="flex items-center justify-between text-[#888] text-[10px] uppercase font-bold pl-1">
            <span>Arquivos Escaneados com Matches</span>
            <FileCode className="w-3.5 h-3.5 text-[#3366FF]" />
          </div>
          <div className="mt-2 text-3xl font-black text-white pl-1">
            {stats.totalFiles}
          </div>
          <div className="mt-1 text-[10px] text-[#00FF41] font-bold pl-1 flex items-center gap-1">
            <Clock className="w-3 h-3 text-[#00FF41]" />
            <span>SLA de Exposição Ativo</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-[#0D0D0D] p-3 border border-[#222] font-mono text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="input-breach-search"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filtrar por nome de arquivo, diretório ou padrão..."
            className="w-full bg-[#050505] border border-[#2A2A2A] focus:border-[#FF3E00] text-white pl-9 pr-8 py-2 text-xs placeholder-[#555] outline-hidden transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[#777] hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Priority Filter Tabs */}
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-[10px] text-[#777] uppercase font-bold mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3 text-[#FF3E00]" />
            Prioridade:
          </span>
          {[
            { key: 'ALL', label: 'Todos' },
            { key: 'P0_CRITICAL', label: 'P0 (Crítico)' },
            { key: 'P1_HIGH', label: 'P1 (Alto)' },
            { key: 'P2_MODERATE', label: 'P2 (Médio)' },
            { key: 'P3_LOW', label: 'P3 (Baixo)' }
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setPriorityFilter(tab.key)}
              className={`px-2.5 py-1 text-[10.5px] border uppercase transition-all cursor-pointer font-bold ${
                priorityFilter === tab.key
                  ? 'bg-[#FF3E00]/20 border-[#FF3E00] text-white'
                  : 'bg-[#141414] border-[#2A2A2A] text-[#888] hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Sort selector */}
        <div className="flex items-center gap-1.5 shrink-0">
          <SlidersHorizontal className="w-3 h-3 text-[#777]" />
          <span className="text-[10px] text-[#777] uppercase font-bold">Ordenar:</span>
          <select
            id="select-breach-sort"
            value={sortMode}
            onChange={(e) => setSortMode(e.target.value as SortMode)}
            className="bg-[#050505] border border-[#2A2A2A] text-white px-2 py-1 text-[11px] outline-hidden focus:border-[#FF3E00] cursor-pointer"
          >
            <option value="FREQUENCY">Maior Frequência</option>
            <option value="RISK">Maior Score de Risco</option>
            <option value="PRIORITY">Prioridade SLA (P0 → P3)</option>
            <option value="NAME">Nome do Arquivo (A-Z)</option>
          </select>
        </div>
      </div>

      {/* Visual Content: Grid / Queue / Chart */}
      {filteredSummaries.length === 0 ? (
        <div className="p-12 text-center bg-[#050505] border border-dashed border-[#222] font-mono space-y-2">
          <CheckCircle2 className="w-8 h-8 text-[#00FF41] mx-auto mb-2" />
          <p className="text-xs text-[#DDD] font-bold">Nenhum arquivo corresponde aos critérios do filtro.</p>
          <p className="text-[11px] text-[#666]">Tente ajustar a busca ou limpar os filtros de prioridade.</p>
          {(priorityFilter !== 'ALL' || searchQuery) && (
            <button
              onClick={() => {
                setPriorityFilter('ALL');
                setSearchQuery('');
              }}
              className="mt-2 px-3 py-1 bg-[#1A1A1A] hover:bg-[#333] text-white text-[10px] uppercase font-bold border border-[#444] transition-colors"
            >
              Limpar Filtros
            </button>
          )}
        </div>
      ) : viewMode === 'GRID' ? (
        /* Thermal Heat Matrix Grid */
        <div className="space-y-4">
          <div 
            id="breach-heatmap-matrix"
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3.5"
          >
            {filteredSummaries.map((item) => {
              const isSelected = selectedFileSummary?.file === item.file;
              return (
                <div
                  key={item.file}
                  id={`breach-tile-${item.fileName.replace(/[^a-zA-Z0-9_-]/g, '_')}`}
                  onClick={() => setSelectedFileSummary(item)}
                  style={{
                    boxShadow: isSelected ? `0 0 15px ${item.thermalColor}60` : undefined
                  }}
                  className={`p-4 bg-[#0A0A0A] border transition-all duration-150 cursor-pointer flex flex-col justify-between group relative overflow-hidden ${
                    isSelected
                      ? 'border-white bg-[#121212]'
                      : 'border-[#222] hover:border-white/50 hover:bg-[#0F0F0F]'
                  }`}
                >
                  {/* Top Thermal Stripe with dynamic width reflecting frequency */}
                  <div 
                    className="absolute top-0 left-0 h-1 transition-all"
                    style={{ 
                      width: `${item.thermalIntensity}%`, 
                      backgroundColor: item.thermalColor 
                    }} 
                  />

                  <div>
                    {/* Top Row: Priority Badge & Match Frequency Pill */}
                    <div className="flex items-center justify-between gap-2 mb-2 font-mono text-[10px]">
                      <span 
                        className="px-1.5 py-0.5 font-black uppercase tracking-wider rounded-xs border text-[9px]"
                        style={{
                          backgroundColor: `${item.thermalColor}18`,
                          color: item.thermalColor,
                          borderColor: `${item.thermalColor}50`
                        }}
                      >
                        {item.priorityLabel}
                      </span>

                      <span 
                        className="inline-flex items-center gap-1 font-mono font-bold px-2 py-0.5 rounded-xs"
                        style={{
                          backgroundColor: `${item.thermalColor}25`,
                          color: item.thermalColor
                        }}
                      >
                        <Flame className="w-3 h-3" />
                        <span>{item.matchCount} {item.matchCount === 1 ? 'match' : 'matches'}</span>
                      </span>
                    </div>

                    {/* File Name & Path */}
                    <div className="space-y-0.5">
                      <h4 
                        className="text-xs sm:text-[13px] font-bold text-white group-hover:text-[#FF3E00] transition-colors truncate font-mono" 
                        title={item.file}
                      >
                        {item.fileName}
                      </h4>
                      <p className="text-[10px] font-mono text-[#666] truncate" title={item.directory}>
                        {item.directory}/
                      </p>
                    </div>

                    {/* Severity mini-indicators */}
                    <div className="flex items-center gap-1 mt-3 font-mono text-[9px]">
                      {item.criticalCount > 0 && (
                        <span className="px-1.5 py-0.2 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-bold">
                          {item.criticalCount} CRIT
                        </span>
                      )}
                      {item.highCount > 0 && (
                        <span className="px-1.5 py-0.2 bg-[#FF7A00]/20 text-[#FF7A00] border border-[#FF7A00]/40 font-bold">
                          {item.highCount} HIGH
                        </span>
                      )}
                      {item.mediumCount > 0 && (
                        <span className="px-1.5 py-0.2 bg-[#EAB308]/20 text-[#EAB308] border border-[#EAB308]/40 font-bold">
                          {item.mediumCount} MED
                        </span>
                      )}
                      {item.lowCount > 0 && (
                        <span className="px-1.5 py-0.2 bg-[#3366FF]/20 text-[#3366FF] border border-[#3366FF]/40 font-bold">
                          {item.lowCount} LOW
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Bottom Footer: Distinct Rules preview and SLA */}
                  <div className="mt-4 pt-2.5 border-t border-[#1C1C1C] flex items-center justify-between font-mono text-[9.5px] text-[#777]">
                    <span className="truncate max-w-[140px]" title={item.distinctRules.join(', ')}>
                      {item.distinctRules[0] || 'Vulnerabilidade'}
                      {item.distinctRules.length > 1 && ` +${item.distinctRules.length - 1}`}
                    </span>
                    <span className="text-[#AAA] font-bold shrink-0">
                      SLA: {item.slaWindow}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Color Legend for Grid */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-[#0A0A0A] border border-[#222] font-mono text-[10.5px]">
            <span className="text-[#888] uppercase font-bold flex items-center gap-1">
              <Info className="w-3.5 h-3.5 text-[#FF3E00]" />
              Gradiente Térmico de Violação:
            </span>
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center gap-1.5 text-white">
                <span className="w-2.5 h-2.5 bg-[#FF3E00] border border-[#FF3E00]/50" />
                <span>P0 Imediato (≥5 matches ou Crítico)</span>
              </span>
              <span className="flex items-center gap-1.5 text-white">
                <span className="w-2.5 h-2.5 bg-[#FF7A00] border border-[#FF7A00]/50" />
                <span>P1 Alta Urgência (3-4 matches)</span>
              </span>
              <span className="flex items-center gap-1.5 text-white">
                <span className="w-2.5 h-2.5 bg-[#EAB308] border border-[#EAB308]/50" />
                <span>P2 Moderado (2 matches)</span>
              </span>
              <span className="flex items-center gap-1.5 text-white">
                <span className="w-2.5 h-2.5 bg-[#3366FF] border border-[#3366FF]/50" />
                <span>P3 Rotina (1 match)</span>
              </span>
            </div>
          </div>
        </div>
      ) : viewMode === 'QUEUE' ? (
        /* Remediation Priority Queue Table */
        <div className="overflow-x-auto border border-[#222] bg-[#0A0A0A]">
          <table className="w-full text-left border-collapse font-mono text-xs">
            <thead>
              <tr className="border-b border-[#222] bg-[#0E0E0E] text-[10px] text-[#888] uppercase tracking-wider">
                <th className="py-3 px-4">Prioridade & SLA</th>
                <th className="py-3 px-4">Arquivo & Diretório</th>
                <th className="py-3 px-4 text-center">Frequência de Padrões</th>
                <th className="py-3 px-4">Severidades</th>
                <th className="py-3 px-4 text-center">Score de Risco</th>
                <th className="py-3 px-4 text-right">Ação de Mitigação</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1A1A1A]">
              {filteredSummaries.map((item, idx) => (
                <tr 
                  key={item.file}
                  onClick={() => setSelectedFileSummary(item)}
                  className="hover:bg-[#141414] transition-colors cursor-pointer group"
                >
                  {/* Priority & SLA */}
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex flex-col gap-1">
                      <span 
                        className="inline-block px-2 py-0.5 font-bold uppercase rounded-xs border text-[9px] w-max"
                        style={{
                          backgroundColor: `${item.thermalColor}20`,
                          color: item.thermalColor,
                          borderColor: `${item.thermalColor}50`
                        }}
                      >
                        {item.priorityLabel}
                      </span>
                      <span className="text-[10px] text-[#777] flex items-center gap-1">
                        <Clock className="w-3 h-3 text-[#777]" />
                        <span>SLA: {item.slaWindow}</span>
                      </span>
                    </div>
                  </td>

                  {/* File Name & Path */}
                  <td className="py-3 px-4">
                    <div className="font-bold text-white group-hover:text-[#FF3E00] transition-colors">
                      {item.fileName}
                    </div>
                    <div className="text-[10px] text-[#666] truncate max-w-xs sm:max-w-sm">
                      {item.directory}/
                    </div>
                  </td>

                  {/* Frequency Progress Bar */}
                  <td className="py-3 px-4 text-center">
                    <div className="inline-flex items-center gap-2">
                      <span className="text-sm font-black text-white" style={{ color: item.thermalColor }}>
                        {item.matchCount}
                      </span>
                      <div className="w-16 sm:w-24 h-2 bg-[#1C1C1C] rounded-xs overflow-hidden">
                        <div 
                          className="h-full transition-all"
                          style={{ 
                            width: `${item.thermalIntensity}%`, 
                            backgroundColor: item.thermalColor 
                          }}
                        />
                      </div>
                    </div>
                  </td>

                  {/* Severities breakdown */}
                  <td className="py-3 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1 text-[9px]">
                      {item.criticalCount > 0 && (
                        <span className="px-1.5 py-0.5 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40 font-bold">
                          {item.criticalCount}C
                        </span>
                      )}
                      {item.highCount > 0 && (
                        <span className="px-1.5 py-0.5 bg-[#FF7A00]/20 text-[#FF7A00] border border-[#FF7A00]/40 font-bold">
                          {item.highCount}H
                        </span>
                      )}
                      {item.mediumCount > 0 && (
                        <span className="px-1.5 py-0.5 bg-[#EAB308]/20 text-[#EAB308] border border-[#EAB308]/40 font-bold">
                          {item.mediumCount}M
                        </span>
                      )}
                      {item.lowCount > 0 && (
                        <span className="px-1.5 py-0.5 bg-[#3366FF]/20 text-[#3366FF] border border-[#3366FF]/40 font-bold">
                          {item.lowCount}L
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Risk Index */}
                  <td className="py-3 px-4 text-center whitespace-nowrap">
                    <span className="px-2 py-0.5 bg-[#141414] border border-[#333] font-bold text-white text-[11px]">
                      {item.riskIndex} / 100
                    </span>
                  </td>

                  {/* Quick Action */}
                  <td className="py-3 px-4 text-right whitespace-nowrap">
                    <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        onClick={() => handleCopyRemediationReport(item)}
                        className="p-1.5 bg-[#141414] hover:bg-[#222] border border-[#333] text-[#AAA] hover:text-white transition-colors cursor-pointer"
                        title="Copiar ticket de remediação do arquivo"
                      >
                        {copiedFile === item.file ? (
                          <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>

                      {onNavigateToFile && (
                        <button
                          type="button"
                          onClick={() => onNavigateToFile(item.file)}
                          className="px-2.5 py-1 bg-[#FF3E00]/15 hover:bg-[#FF3E00] border border-[#FF3E00]/40 text-[#FF3E00] hover:text-white font-bold text-[10px] uppercase transition-all flex items-center gap-1 cursor-pointer"
                          title="Inspecionar no Scanner"
                        >
                          <span>Inspecionar</span>
                          <ArrowUpRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        /* Chart Mode: Frequency Distribution Bar Chart */
        <div className="bg-[#0A0A0A] border border-[#222] p-5 space-y-4 font-mono">
          <div className="flex items-center justify-between pb-2 border-b border-[#1A1A1A]">
            <div>
              <h3 className="text-xs font-bold text-white uppercase flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-[#FF3E00]" />
                <span>Top 10 Arquivos por Volume de Padrões Sensíveis</span>
              </h3>
              <p className="text-[10px] text-[#777]">Distribuição de severidade empilhada por arquivo</p>
            </div>
            <span className="text-[10px] text-[#888]">Eixo Y: Total de Padrões</span>
          </div>

          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 20, left: -10, bottom: 25 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#222" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  stroke="#666" 
                  tick={{ fill: '#AAA', fontSize: 10, fontFamily: 'monospace' }}
                  angle={-20}
                  textAnchor="end"
                />
                <YAxis 
                  stroke="#666" 
                  tick={{ fill: '#AAA', fontSize: 10, fontFamily: 'monospace' }} 
                  allowDecimals={false}
                />
                <RechartsTooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="bg-[#080808] border border-white/20 p-3 shadow-xl font-mono text-xs space-y-1">
                          <p className="text-white font-bold truncate max-w-xs">{data.fullName}</p>
                          <p className="text-[#FF3E00] font-black">{data.total} achados totais</p>
                          <div className="text-[10px] text-[#AAA] space-y-0.5 pt-1 border-t border-[#222]">
                            <div>Crítico: <span className="text-[#FF3E00] font-bold">{data.critical}</span></div>
                            <div>Alto: <span className="text-[#FF7A00] font-bold">{data.high}</span></div>
                            <div>Médio: <span className="text-[#EAB308] font-bold">{data.medium}</span></div>
                            <div>Baixo: <span className="text-[#3366FF] font-bold">{data.low}</span></div>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Legend 
                  verticalAlign="top" 
                  align="right"
                  wrapperStyle={{ fontSize: '10px', paddingBottom: '8px' }}
                />
                <Bar dataKey="critical" name="Crítico" fill="#FF3E00" stackId="a" />
                <Bar dataKey="high" name="Alto" fill="#FF7A00" stackId="a" />
                <Bar dataKey="medium" name="Médio" fill="#EAB308" stackId="a" />
                <Bar dataKey="low" name="Baixo" fill="#3366FF" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Selected File Remediation Deep-Dive Inspection Card */}
      {selectedFileSummary && (
        <div 
          id="breach-detail-inspection-card"
          className="p-5 sm:p-6 bg-[#0E0E0E] border-2 border-[#333] space-y-4 font-mono relative animate-in fade-in duration-150"
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#222]">
            <div className="space-y-1 min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span 
                  className="px-2 py-0.5 font-bold uppercase rounded-xs border text-[9.5px]"
                  style={{
                    backgroundColor: `${selectedFileSummary.thermalColor}20`,
                    color: selectedFileSummary.thermalColor,
                    borderColor: `${selectedFileSummary.thermalColor}50`
                  }}
                >
                  {selectedFileSummary.priorityLabel}
                </span>
                <span className="text-[10px] text-[#888] font-bold">
                  SLA Máximo: <strong className="text-white">{selectedFileSummary.slaWindow}</strong>
                </span>
              </div>

              <h3 className="text-base font-bold text-white truncate" title={selectedFileSummary.file}>
                {selectedFileSummary.file}
              </h3>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => handleCopyRemediationReport(selectedFileSummary)}
                className="px-3 py-1.5 bg-[#1C1C1C] hover:bg-[#2A2A2A] border border-[#333] text-white font-mono text-xs uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Copiar relatório estruturado de remediação"
              >
                {copiedFile === selectedFileSummary.file ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-[#00FF41]" />
                    <span className="text-[#00FF41]">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-[#AAA]" />
                    <span>Copiar Ticket</span>
                  </>
                )}
              </button>

              {onNavigateToFile && (
                <button
                  type="button"
                  onClick={() => onNavigateToFile(selectedFileSummary.file)}
                  className="px-3.5 py-1.5 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-mono text-xs uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer shadow-[0_0_15px_rgba(255,62,0,0.3)]"
                >
                  <span>Abrir no Scanner</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              )}

              <button
                type="button"
                onClick={() => setSelectedFileSummary(null)}
                className="p-1.5 rounded-sm hover:bg-white/10 text-[#888] hover:text-white transition-colors cursor-pointer"
                title="Fechar detalhes"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Quick Metrics Bar for Selected File */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 bg-[#050505] border border-[#222]">
              <span className="text-[10px] text-[#777] uppercase block">Frequência Total:</span>
              <span className="text-lg font-black text-white" style={{ color: selectedFileSummary.thermalColor }}>
                {selectedFileSummary.matchCount} ocorrências
              </span>
            </div>
            <div className="p-2.5 bg-[#050505] border border-[#222]">
              <span className="text-[10px] text-[#777] uppercase block">Score de Risco:</span>
              <span className="text-lg font-black text-white">
                {selectedFileSummary.riskIndex} / 100
              </span>
            </div>
            <div className="p-2.5 bg-[#050505] border border-[#222]">
              <span className="text-[10px] text-[#777] uppercase block">Padrões Distintos:</span>
              <span className="text-lg font-black text-white">
                {selectedFileSummary.distinctRules.length} tipos
              </span>
            </div>
            <div className="p-2.5 bg-[#050505] border border-[#222]">
              <span className="text-[10px] text-[#777] uppercase block">Entropia Máxima:</span>
              <span className="text-lg font-black text-[#00FF41]">
                {selectedFileSummary.maxEntropy} bits
              </span>
            </div>
          </div>

          {/* Finding items list in this file */}
          <div className="space-y-2 pt-2">
            <div className="text-[10.5px] text-[#AAA] font-bold uppercase tracking-wider">
              Padrões Detectados neste Arquivo ({selectedFileSummary.findings.length}):
            </div>
            <div className="max-h-60 overflow-y-auto space-y-2 pr-1 scrollbar-thin">
              {selectedFileSummary.findings.map((finding) => (
                <div 
                  key={finding.id}
                  onClick={() => onSelectFinding && onSelectFinding(finding)}
                  className="p-2.5 bg-[#050505] border border-[#222] hover:border-[#FF3E00] flex flex-col sm:flex-row sm:items-center justify-between gap-2 cursor-pointer transition-colors"
                >
                  <div className="space-y-0.5 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.2 text-[9px] font-black uppercase rounded-xs ${
                        finding.severity === 'CRITICAL' ? 'bg-[#FF3E00] text-white' :
                        finding.severity === 'HIGH' ? 'bg-[#FF7A00] text-black font-bold' :
                        'bg-[#EAB308] text-black font-bold'
                      }`}>
                        {finding.severity}
                      </span>
                      <span className="font-bold text-white text-xs">{finding.ruleName}</span>
                      <span className="text-[10px] text-[#777]">Linha {finding.line}</span>
                    </div>
                    <div className="text-[10px] text-[#AAA] font-mono truncate max-w-lg">
                      Segredo Mascarado: <span className="text-[#FF3E00] font-bold">{finding.maskedSecret}</span>
                    </div>
                  </div>

                  <div className="text-[10px] text-emerald-400/90 sm:text-right shrink-0">
                    <span className="hidden sm:inline">Ação: </span>
                    <span className="font-bold">{finding.remediation || 'Revogar chave imediatamente'}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
