import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Flame, 
  Search, 
  Sliders, 
  ArrowUpDown, 
  ChevronRight, 
  Info, 
  AlertTriangle, 
  Sparkles, 
  Filter,
  Layers,
  FileCode,
  Gauge
} from 'lucide-react';
import { ScanFinding, SeverityLevel } from '../types';

interface FindingRiskScoreTableProps {
  findings: ScanFinding[];
  onSelectFinding: (finding: ScanFinding) => void;
  onNavigateToScanner?: () => void;
}

export const FindingRiskScoreTable: React.FC<FindingRiskScoreTableProps> = ({
  findings,
  onSelectFinding,
  onNavigateToScanner
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<SeverityLevel | 'ALL'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');

  // Compute key summary metrics
  const { avgScore, maxScore, tierCounts, tierAverages } = useMemo(() => {
    if (findings.length === 0) {
      return {
        avgScore: 0,
        maxScore: 0,
        tierCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        tierAverages: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
      };
    }

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const sums = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    let totalScore = 0;
    let max = 0;

    findings.forEach((f) => {
      const score = f.riskScore ?? 0;
      totalScore += score;
      if (score > max) max = score;

      const sev = (f.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW');
      if (counts[sev] !== undefined) {
        counts[sev] += 1;
        sums[sev] += score;
      }
    });

    return {
      avgScore: Math.round(totalScore / findings.length),
      maxScore: max,
      tierCounts: counts,
      tierAverages: {
        CRITICAL: counts.CRITICAL > 0 ? Math.round(sums.CRITICAL / counts.CRITICAL) : 0,
        HIGH: counts.HIGH > 0 ? Math.round(sums.HIGH / counts.HIGH) : 0,
        MEDIUM: counts.MEDIUM > 0 ? Math.round(sums.MEDIUM / counts.MEDIUM) : 0,
        LOW: counts.LOW > 0 ? Math.round(sums.LOW / counts.LOW) : 0
      }
    };
  }, [findings]);

  // Filtered and sorted findings
  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) {
          return false;
        }
        if (searchTerm.trim()) {
          const q = searchTerm.toLowerCase();
          const matchRule = f.ruleName.toLowerCase().includes(q) || f.ruleId.toLowerCase().includes(q);
          const matchFile = f.file.toLowerCase().includes(q);
          const matchCategory = f.category.toLowerCase().includes(q);
          return matchRule || matchFile || matchCategory;
        }
        return true;
      })
      .sort((a, b) => {
        const scoreA = a.riskScore ?? 0;
        const scoreB = b.riskScore ?? 0;
        return sortOrder === 'desc' ? scoreB - scoreA : scoreA - scoreB;
      });
  }, [findings, selectedSeverity, searchTerm, sortOrder]);

  const getScoreColor = (score: number) => {
    if (score >= 80) return { text: 'text-[#FF3E00]', bg: 'bg-[#FF3E00]', badgeBg: 'bg-[#FF3E00]/15 border-[#FF3E00]/40 text-[#FF3E00]' };
    if (score >= 60) return { text: 'text-[#FF7A00]', bg: 'bg-[#FF7A00]', badgeBg: 'bg-[#FF7A00]/15 border-[#FF7A00]/40 text-[#FF7A00]' };
    if (score >= 35) return { text: 'text-[#EAB308]', bg: 'bg-[#EAB308]', badgeBg: 'bg-[#EAB308]/15 border-[#EAB308]/40 text-[#EAB308]' };
    return { text: 'text-[#3366FF]', bg: 'bg-[#3366FF]', badgeBg: 'bg-[#3366FF]/15 border-[#3366FF]/40 text-[#3366FF]' };
  };

  return (
    <div id="finding-risk-score-matrix" className="bg-[#080808] border-2 border-[#2A2A2A] p-6 lg:p-8 space-y-6 relative overflow-hidden">
      {/* Background radial accent */}
      <div className="absolute top-0 right-0 w-48 h-48 bg-[#FF3E00]/5 rounded-bl-full pointer-events-none" />

      {/* Header section */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222]">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono text-[#FF3E00] bg-[#FF3E00]/10 px-2.5 py-0.5 border border-[#FF3E00]/40 uppercase font-black tracking-widest flex items-center gap-1.5">
              <Gauge className="w-3.5 h-3.5" />
              SCANNER ENGINE // RISK SCORING MODEL
            </span>
            <span className="text-[10px] font-mono text-[#888]">
              PONTUAÇÃO INDIVIDUAL POR ACHADO (0-100)
            </span>
            <span className="text-[10px] font-mono bg-[#141414] text-[#00FF41] border border-[#00FF41]/30 px-2 py-0.5 font-bold">
              CLASSIFICAÇÃO DINÂMICA
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-black uppercase tracking-tight text-white flex items-center gap-2.5">
            <span>Matriz de Risk Score por Vulnerabilidade</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-3xl leading-relaxed">
            Cada vulnerabilidade detectada recebe um <strong className="text-white">Risk Score (0 a 100)</strong> calculado pelo serviço do scanner com base no peso da regra correspondente, categoria de exposição, entropia de Shannon e criticidade do arquivo hospedeiro. A severidade (<strong className="text-[#FF3E00]">Crítica</strong>, <strong className="text-[#FF7A00]">Alta</strong>, <strong className="text-[#EAB308]">Média</strong> ou <strong className="text-[#3366FF]">Baixa</strong>) é atribuída diretamente a partir desse cálculo.
          </p>
        </div>

        {onNavigateToScanner && (
          <button
            onClick={onNavigateToScanner}
            className="px-5 py-3 bg-[#111] hover:bg-[#FF3E00] hover:text-white border border-[#333] hover:border-[#FF3E00] text-white font-mono text-xs uppercase tracking-wider flex items-center gap-2 transition-all shrink-0 cursor-pointer"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Ver no Scanner ({findings.length})</span>
          </button>
        )}
      </div>

      {/* KPI Cards: Average & Peak Risk Score + Severity Tiers */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Metric 1: Average Finding Risk Score */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-[#888] uppercase font-bold">Média dos Scores</div>
          <div className="my-2">
            <div className="flex items-baseline gap-1">
              <span className={`text-3xl font-black font-mono ${getScoreColor(avgScore).text}`}>
                {avgScore}
              </span>
              <span className="text-[10px] font-mono text-[#666]">/100</span>
            </div>
            <div className="text-[9px] font-mono text-[#777]">Score médio global</div>
          </div>
          <div className="w-full bg-[#1A1A1A] h-1.5 rounded-none overflow-hidden">
            <div 
              className={`h-full ${getScoreColor(avgScore).bg} transition-all duration-500`}
              style={{ width: `${avgScore}%` }}
            />
          </div>
        </div>

        {/* Metric 2: Peak Risk Score */}
        <div className="p-4 bg-[#0D0D0D] border border-[#222] flex flex-col justify-between">
          <div className="text-[10px] font-mono text-[#888] uppercase font-bold">Pico de Risco (Max)</div>
          <div className="my-2">
            <div className="flex items-baseline gap-1">
              <span className={`text-3xl font-black font-mono ${getScoreColor(maxScore).text}`}>
                {maxScore}
              </span>
              <span className="text-[10px] font-mono text-[#666]">/100</span>
            </div>
            <div className="text-[9px] font-mono text-[#777]">Maior pontuação unitária</div>
          </div>
          <div className="w-full bg-[#1A1A1A] h-1.5 rounded-none overflow-hidden">
            <div 
              className={`h-full ${getScoreColor(maxScore).bg} transition-all duration-500`}
              style={{ width: `${maxScore}%` }}
            />
          </div>
        </div>

        {/* Metric 3: Critical Tier (Score >= 80) */}
        <button
          onClick={() => setSelectedSeverity(selectedSeverity === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
          className={`p-4 border text-left transition-all cursor-pointer flex flex-col justify-between ${
            selectedSeverity === 'CRITICAL'
              ? 'bg-[#220700] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.25)]'
              : 'bg-[#0D0D0D] border-[#222] hover:border-[#FF3E00]/60'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#FF3E00] uppercase font-bold">CRÍTICO (≥80)</span>
            <span className="w-2 h-2 rounded-full bg-[#FF3E00]" />
          </div>
          <div className="my-2">
            <div className="text-3xl font-black font-mono text-white">
              {tierCounts.CRITICAL}
            </div>
            <div className="text-[9px] font-mono text-[#888]">
              Score Médio: <strong className="text-[#FF3E00]">{tierAverages.CRITICAL} pts</strong>
            </div>
          </div>
          <div className="text-[8.5px] font-mono text-[#AAA]">Clique para filtrar</div>
        </button>

        {/* Metric 4: High Tier (Score 60-79) */}
        <button
          onClick={() => setSelectedSeverity(selectedSeverity === 'HIGH' ? 'ALL' : 'HIGH')}
          className={`p-4 border text-left transition-all cursor-pointer flex flex-col justify-between ${
            selectedSeverity === 'HIGH'
              ? 'bg-[#200C00] border-[#FF7A00] shadow-[0_0_15px_rgba(255,122,0,0.25)]'
              : 'bg-[#0D0D0D] border-[#222] hover:border-[#FF7A00]/60'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#FF7A00] uppercase font-bold">ALTO (60-79)</span>
            <span className="w-2 h-2 rounded-full bg-[#FF7A00]" />
          </div>
          <div className="my-2">
            <div className="text-3xl font-black font-mono text-white">
              {tierCounts.HIGH}
            </div>
            <div className="text-[9px] font-mono text-[#888]">
              Score Médio: <strong className="text-[#FF7A00]">{tierAverages.HIGH} pts</strong>
            </div>
          </div>
          <div className="text-[8.5px] font-mono text-[#AAA]">Clique para filtrar</div>
        </button>

        {/* Metric 5: Medium Tier (Score 35-59) */}
        <button
          onClick={() => setSelectedSeverity(selectedSeverity === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
          className={`p-4 border text-left transition-all cursor-pointer flex flex-col justify-between ${
            selectedSeverity === 'MEDIUM'
              ? 'bg-[#1F1800] border-[#EAB308] shadow-[0_0_15px_rgba(234,179,8,0.25)]'
              : 'bg-[#0D0D0D] border-[#222] hover:border-[#EAB308]/60'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#EAB308] uppercase font-bold">MÉDIO (35-59)</span>
            <span className="w-2 h-2 rounded-full bg-[#EAB308]" />
          </div>
          <div className="my-2">
            <div className="text-3xl font-black font-mono text-white">
              {tierCounts.MEDIUM}
            </div>
            <div className="text-[9px] font-mono text-[#888]">
              Score Médio: <strong className="text-[#EAB308]">{tierAverages.MEDIUM} pts</strong>
            </div>
          </div>
          <div className="text-[8.5px] font-mono text-[#AAA]">Clique para filtrar</div>
        </button>

        {/* Metric 6: Low Tier (Score < 35) */}
        <button
          onClick={() => setSelectedSeverity(selectedSeverity === 'LOW' ? 'ALL' : 'LOW')}
          className={`p-4 border text-left transition-all cursor-pointer flex flex-col justify-between ${
            selectedSeverity === 'LOW'
              ? 'bg-[#051124] border-[#3366FF] shadow-[0_0_15px_rgba(51,102,255,0.25)]'
              : 'bg-[#0D0D0D] border-[#222] hover:border-[#3366FF]/60'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-[#3366FF] uppercase font-bold">BAIXO (&lt;35)</span>
            <span className="w-2 h-2 rounded-full bg-[#3366FF]" />
          </div>
          <div className="my-2">
            <div className="text-3xl font-black font-mono text-white">
              {tierCounts.LOW}
            </div>
            <div className="text-[9px] font-mono text-[#888]">
              Score Médio: <strong className="text-[#3366FF]">{tierAverages.LOW} pts</strong>
            </div>
          </div>
          <div className="text-[8.5px] font-mono text-[#AAA]">Clique para filtrar</div>
        </button>
      </div>

      {/* Filter Bar & Sort Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
        {/* Search Input */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Buscar por regra, arquivo ou categoria..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#050505] border border-[#222] focus:border-[#FF3E00] text-white font-mono text-xs pl-9 pr-3 py-2 outline-none transition-colors"
          />
        </div>

        {/* Severity Filter Pills & Sort Button */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center bg-[#0D0D0D] border border-[#222] p-0.5">
            <button
              onClick={() => setSelectedSeverity('ALL')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-colors ${
                selectedSeverity === 'ALL'
                  ? 'bg-white text-black'
                  : 'text-[#888] hover:text-white'
              }`}
            >
              Todos ({findings.length})
            </button>
            <button
              onClick={() => setSelectedSeverity('CRITICAL')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-colors ${
                selectedSeverity === 'CRITICAL'
                  ? 'bg-[#FF3E00] text-white'
                  : 'text-[#888] hover:text-[#FF3E00]'
              }`}
            >
              Crítico ({tierCounts.CRITICAL})
            </button>
            <button
              onClick={() => setSelectedSeverity('HIGH')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-colors ${
                selectedSeverity === 'HIGH'
                  ? 'bg-[#FF7A00] text-black'
                  : 'text-[#888] hover:text-[#FF7A00]'
              }`}
            >
              Alto ({tierCounts.HIGH})
            </button>
            <button
              onClick={() => setSelectedSeverity('MEDIUM')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-colors ${
                selectedSeverity === 'MEDIUM'
                  ? 'bg-[#EAB308] text-black'
                  : 'text-[#888] hover:text-[#EAB308]'
              }`}
            >
              Médio ({tierCounts.MEDIUM})
            </button>
            <button
              onClick={() => setSelectedSeverity('LOW')}
              className={`px-2.5 py-1 text-[10px] font-mono uppercase font-bold transition-colors ${
                selectedSeverity === 'LOW'
                  ? 'bg-[#3366FF] text-white'
                  : 'text-[#888] hover:text-[#3366FF]'
              }`}
            >
              Baixo ({tierCounts.LOW})
            </button>
          </div>

          <button
            onClick={() => setSortOrder(prev => prev === 'desc' ? 'asc' : 'desc')}
            className="px-3 py-2 bg-[#0D0D0D] hover:bg-[#1A1A1A] border border-[#222] text-white font-mono text-[10px] uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
            title="Alternar ordenação por pontuação de risco"
          >
            <ArrowUpDown className="w-3 h-3 text-[#FF3E00]" />
            <span>Score: {sortOrder === 'desc' ? 'Maior → Menor' : 'Menor → Maior'}</span>
          </button>
        </div>
      </div>

      {/* Findings Risk Score Cards Table */}
      <div className="space-y-3">
        {filteredFindings.length === 0 ? (
          <div className="p-10 text-center bg-[#050505] border border-dashed border-[#222]">
            <ShieldCheck className="w-8 h-8 text-[#00FF41] mx-auto mb-2" />
            <p className="text-xs font-mono text-[#AAA]">Nenhum achado encontrado para os filtros selecionados.</p>
            <p className="text-[10px] font-mono text-[#666] mt-1">Altere os critérios de severidade ou o termo de busca.</p>
          </div>
        ) : (
          filteredFindings.map((finding) => {
            const score = finding.riskScore ?? 0;
            const theme = getScoreColor(score);
            const details = finding.riskScoreDetails;

            return (
              <div
                key={finding.id}
                onClick={() => onSelectFinding(finding)}
                className="p-4 sm:p-5 bg-[#0A0A0A] border border-[#222] hover:border-[#FF3E00] transition-all cursor-pointer group space-y-3"
              >
                {/* Top row: Severity + Rule + Risk Score Badge */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Severity Pill */}
                    <span className={`text-[9px] font-mono font-black px-2 py-0.5 uppercase tracking-wider ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-[#FF3E00] text-white'
                        : finding.severity === 'HIGH'
                        ? 'bg-[#FF7A00] text-black font-bold'
                        : finding.severity === 'MEDIUM'
                        ? 'bg-[#EAB308] text-black font-bold'
                        : 'bg-[#3366FF] text-white'
                    }`}>
                      {finding.severity}
                    </span>

                    {/* Rule Title */}
                    <span className="text-sm font-bold text-white group-hover:text-[#FF3E00] transition-colors">
                      {finding.ruleName}
                    </span>

                    {/* Category */}
                    <span className="text-[10px] font-mono text-[#888] bg-[#141414] px-2 py-0.5 border border-[#262626]">
                      {finding.category}
                    </span>
                  </div>

                  {/* Prominent Risk Score Gauge Indicator */}
                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <div className="text-[9px] font-mono text-[#888] uppercase">Calculated Risk Score</div>
                      <div className="flex items-baseline justify-end gap-1">
                        <span className={`text-xl font-black font-mono ${theme.text}`}>
                          {score}
                        </span>
                        <span className="text-[10px] font-mono text-[#666]">/ 100</span>
                      </div>
                    </div>

                    <div className="w-16 sm:w-24 bg-[#1A1A1A] h-2.5 rounded-none overflow-hidden border border-[#333]">
                      <div 
                        className={`h-full ${theme.bg} transition-all duration-300`}
                        style={{ width: `${score}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Secret snippet & file path */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-3 pt-2 border-t border-[#141414] items-center">
                  <div className="md:col-span-8 flex flex-wrap items-center gap-2 text-xs font-mono">
                    <span className="text-[#888] flex items-center gap-1">
                      <FileCode className="w-3.5 h-3.5 text-[#666]" />
                      <span className="text-white font-bold">{finding.file}</span>
                      <span>:{finding.line}</span>
                    </span>

                    <span className="text-[#444]">•</span>

                    <span className="text-[11px] text-[#AAA] bg-[#000] px-2 py-0.5 border border-[#1C1C1C] truncate max-w-xs sm:max-w-md">
                      Secret: <strong className="text-[#FF3E00]">{finding.maskedSecret}</strong>
                    </span>

                    <span className="text-[#444]">•</span>

                    <span className="text-[10px] text-[#888]">
                      Entropia: <strong className="text-white">{finding.entropy.toFixed(2)}</strong>
                    </span>
                  </div>

                  <div className="md:col-span-4 flex items-center justify-end gap-2 text-[10px] font-mono">
                    <span className="text-[#666] group-hover:text-white transition-colors flex items-center gap-1">
                      <span>Inspecionar no código</span>
                      <ChevronRight className="w-3 h-3 text-[#FF3E00] group-hover:translate-x-0.5 transition-transform" />
                    </span>
                  </div>
                </div>

                {/* Score Calculation Factors Breakdown */}
                {details && details.factors && details.factors.length > 0 && (
                  <div className="pt-2 border-t border-[#141414] flex flex-wrap items-center gap-1.5 text-[9px] font-mono">
                    <span className="text-[#666] uppercase font-bold mr-1">Fatores do Score:</span>
                    {details.factors.map((factor, fIdx) => (
                      <span 
                        key={fIdx}
                        className="px-2 py-0.5 bg-[#050505] text-[#AAA] border border-[#222]"
                      >
                        {factor}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Footer Info Diagnostic */}
      <div className="p-4 bg-[#0D0D0D] border border-[#222] font-mono text-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-[#888]">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-[#FF3E00] shrink-0" />
          <span>
            O <strong className="text-white">Risk Score</strong> é atualizado automaticamente a cada reescaneamento de arquivos, refletindo mudanças em segredos, parâmetros de entropia e contexto de caminho.
          </span>
        </div>
        <span className="text-[10px] uppercase tracking-wider text-[#666] shrink-0">
          Engine: SAST Regex Engine v2.4
        </span>
      </div>
    </div>
  );
};
