import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Flame, 
  Layers, 
  HelpCircle, 
  ChevronRight, 
  Server, 
  Code2, 
  Cpu, 
  TestTube2, 
  FileWarning, 
  Sliders,
  FileDown,
  Check
} from 'lucide-react';
import { ScanReport, FileCriticalityLevel, SeverityLevel } from '../types';
import { evaluateFileCriticality, SEVERITY_BASE_WEIGHTS, FILE_CRITICALITY_MULTIPLIERS } from '../lib/scanner';
import { downloadSecurityReportPdf } from '../lib/pdfReportGenerator';

interface SecurityImpactPanelProps {
  report: ScanReport;
  onNavigateToFile?: (filePath: string) => void;
  onNavigateToTab?: (tab: string) => void;
}

export const SecurityImpactPanel: React.FC<SecurityImpactPanelProps> = ({
  report,
  onNavigateToFile,
  onNavigateToTab
}) => {
  const { metrics, findings } = report;
  const [isExporting, setIsExporting] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleExport = () => {
    setIsExporting(true);
    try {
      downloadSecurityReportPdf(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } finally {
      setIsExporting(false);
    }
  };

  const score = metrics.securityImpactScore ?? 0;
  const impactLevel = metrics.impactLevel ?? 'NOMINAL';
  const totalWeightedRisk = metrics.totalWeightedRisk ?? 0;

  // Visual styling based on score
  const getImpactTheme = (val: number) => {
    if (val >= 80) {
      return {
        text: 'text-[#FF3E00]',
        bg: 'bg-[#FF3E00]/10',
        border: 'border-[#FF3E00]/40',
        accentBg: 'bg-[#FF3E00]',
        label: 'CRITICAL IMPACT',
        status: 'Ameaça Severa em Infraestrutura Crítica'
      };
    }
    if (val >= 60) {
      return {
        text: 'text-[#FF7A00]',
        bg: 'bg-[#FF7A00]/10',
        border: 'border-[#FF7A00]/40',
        accentBg: 'bg-[#FF7A00]',
        label: 'HIGH IMPACT',
        status: 'Risco Elevado em Serviços Backend/APIs'
      };
    }
    if (val >= 35) {
      return {
        text: 'text-[#EAB308]',
        bg: 'bg-[#EAB308]/10',
        border: 'border-[#EAB308]/40',
        accentBg: 'bg-[#EAB308]',
        label: 'ELEVATED IMPACT',
        status: 'Exposição Moderada Requer Atenção'
      };
    }
    if (val >= 15) {
      return {
        text: 'text-[#3366FF]',
        bg: 'bg-[#3366FF]/10',
        border: 'border-[#3366FF]/40',
        accentBg: 'bg-[#3366FF]',
        label: 'MODERATE IMPACT',
        status: 'Risco Controlado / Superfície Restrita'
      };
    }
    if (val > 0) {
      return {
        text: 'text-[#00FF41]',
        bg: 'bg-[#00FF41]/10',
        border: 'border-[#00FF41]/40',
        accentBg: 'bg-[#00FF41]',
        label: 'LOW IMPACT',
        status: 'Exposição Residual em Testes ou Documentação'
      };
    }
    return {
      text: 'text-[#00FF41]',
      bg: 'bg-[#00FF41]/10',
      border: 'border-[#00FF41]/30',
      accentBg: 'bg-[#00FF41]',
      label: 'NOMINAL (0 RISK)',
      status: 'Nenhum Segredo Ativo Detectado'
    };
  };

  const theme = getImpactTheme(score);

  // Group findings by file and rank by weighted risk
  interface FileRiskSummary {
    file: string;
    criticality: FileCriticalityLevel;
    multiplier: number;
    reason: string;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    totalFindings: number;
    totalRiskPoints: number;
  }

  const fileRiskMap = new Map<string, FileRiskSummary>();

  findings.forEach(f => {
    const critInfo = evaluateFileCriticality(f.file);
    let summary = fileRiskMap.get(f.file);
    if (!summary) {
      summary = {
        file: f.file,
        criticality: critInfo.level,
        multiplier: critInfo.weight,
        reason: critInfo.reason,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        totalFindings: 0,
        totalRiskPoints: 0
      };
      fileRiskMap.set(f.file, summary);
    }

    if (f.severity === 'CRITICAL') summary.criticalCount++;
    else if (f.severity === 'HIGH') summary.highCount++;
    else if (f.severity === 'MEDIUM') summary.mediumCount++;
    else if (f.severity === 'LOW') summary.lowCount++;

    const baseWeight = SEVERITY_BASE_WEIGHTS[f.severity] || 5;
    const itemRisk = f.weightedScore ?? (baseWeight * critInfo.weight);
    summary.totalRiskPoints += itemRisk;
    summary.totalFindings++;
  });

  const rankedFiles = Array.from(fileRiskMap.values()).sort((a, b) => b.totalRiskPoints - a.totalRiskPoints);

  const getCriticalityBadge = (level: FileCriticalityLevel, multiplier: number) => {
    switch (level) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/40 px-2 py-0.5">
            <Server className="w-3 h-3" />
            CRÍTICO ({multiplier}x)
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold bg-[#FF7A00]/15 text-[#FF7A00] border border-[#FF7A00]/40 px-2 py-0.5">
            <Cpu className="w-3 h-3" />
            ALTO ({multiplier}x)
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold bg-[#EAB308]/15 text-[#EAB308] border border-[#EAB308]/40 px-2 py-0.5">
            <Code2 className="w-3 h-3" />
            MÉDIO ({multiplier}x)
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold bg-[#3366FF]/15 text-[#3366FF] border border-[#3366FF]/40 px-2 py-0.5">
            <TestTube2 className="w-3 h-3" />
            BAIXO ({multiplier}x)
          </span>
        );
    }
  };

  return (
    <div className="bg-[#080808] border border-[#222] p-6 lg:p-8 space-y-8">
      {/* Top Banner & Main Score */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1A1A1A]">
        <div className="space-y-2">
          <div className="flex items-center gap-2.5">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // SCANNER ENGINE RISK MATRIX
            </span>
            <span className="text-[10px] font-mono text-[#AAA] bg-[#141414] px-2 py-0.5 border border-[#2A2A2A]">
              WEIGHTED ALGORITHM v2.4
            </span>
            <button
              onClick={handleExport}
              disabled={isExporting}
              className="inline-flex items-center gap-1.5 text-[10px] font-mono font-bold bg-[#FF3E00]/10 hover:bg-[#FF3E00] text-[#FF3E00] hover:text-white border border-[#FF3E00]/30 px-2 py-0.5 uppercase tracking-wider transition-all disabled:opacity-50"
              title="Gerar e baixar PDF consolidado com o cálculo de risco ponderado"
            >
              {copied ? <Check className="w-3 h-3 text-[#00FF41]" /> : <FileDown className="w-3 h-3" />}
              <span>{copied ? 'PDF BAIXADO!' : isExporting ? 'GERANDO...' : 'EXPORTAR PDF'}</span>
            </button>
          </div>
          <h2 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase flex items-center gap-3">
            <Flame className={`w-6 h-6 ${theme.text}`} />
            <span>Security Impact Score</span>
          </h2>
          <p className="text-xs font-mono text-[#888] max-w-2xl leading-relaxed">
            Pontuação ponderada de risco combinando a <strong className="text-white">severidade intrínseca da vulnerabilidade</strong> (OWASP/CWE) com a <strong className="text-white">criticidade arquitetural do arquivo</strong> exposto.
          </p>
        </div>

        {/* Big Score Block */}
        <div className="flex items-center gap-5 bg-[#0D0D0D] border border-[#222] p-5 lg:min-w-[320px] justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-wider text-[#666] mb-1">
              Impact Score (0 - 100)
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-5xl sm:text-6xl font-black tracking-tighter ${theme.text}`}>
                {score}
              </span>
              <span className="text-lg font-mono text-[#555] font-bold">/ 100</span>
            </div>
            <div className="text-[11px] font-mono text-[#AAA] mt-1">
              Carga Bruta: <span className="text-white font-bold">{totalWeightedRisk}</span> pts
            </div>
          </div>

          <div className="flex flex-col items-end gap-2">
            <div className={`px-2.5 py-1 text-[11px] font-mono font-black border ${theme.bg} ${theme.border} ${theme.text} uppercase tracking-wider`}>
              {theme.label}
            </div>
            <span className="text-[10px] font-mono text-[#777] text-right max-w-[140px] leading-tight">
              {theme.status}
            </span>
          </div>
        </div>
      </div>

      {/* Visual Risk Gauge / Continuous Progress Spectrum */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-[11px] font-mono text-[#888]">
          <span className="uppercase font-bold tracking-wider text-white">Nível de Exposição de Risco</span>
          <span>{score}% Saturado</span>
        </div>

        <div className="relative h-4 bg-[#141414] border border-[#222] overflow-hidden">
          {/* Background Zone Tiers */}
          <div className="absolute inset-0 flex">
            <div className="w-[15%] h-full bg-[#00FF41]/15 border-r border-[#000]/40" title="0 - 14: Baixo"></div>
            <div className="w-[20%] h-full bg-[#3366FF]/15 border-r border-[#000]/40" title="15 - 34: Moderado"></div>
            <div className="w-[25%] h-full bg-[#EAB308]/15 border-r border-[#000]/40" title="35 - 59: Elevado"></div>
            <div className="w-[20%] h-full bg-[#FF7A00]/20 border-r border-[#000]/40" title="60 - 79: Alto"></div>
            <div className="w-[20%] h-full bg-[#FF3E00]/25" title="80 - 100: Crítico"></div>
          </div>

          {/* Active Filled Bar */}
          <div 
            className={`h-full transition-all duration-700 relative z-10 ${theme.accentBg}`}
            style={{ width: `${Math.max(2, Math.min(100, score))}%` }}
          />
        </div>

        {/* Zone Labels */}
        <div className="grid grid-cols-5 text-[9px] font-mono text-[#666] pt-1 uppercase tracking-wider">
          <div className="text-left text-[#00FF41]">0-14 NOMINAL/LOW</div>
          <div className="text-center text-[#3366FF]">15-34 MODERATE</div>
          <div className="text-center text-[#EAB308]">35-59 ELEVATED</div>
          <div className="text-center text-[#FF7A00]">60-79 HIGH</div>
          <div className="text-right text-[#FF3E00]">80-100 CRITICAL</div>
        </div>
      </div>

      {/* 2 Core Weighting Dimensions Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Dimension 1: Finding Severity Base Weights */}
        <div className="bg-[#0D0D0D] border border-[#1F1F1F] p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#1A1A1A]">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-[#FF3E00]" />
              <span className="text-xs font-black tracking-wider text-white uppercase">1. Severidade Base</span>
            </div>
            <span className="text-[10px] font-mono text-[#666]">Pontos Fixos</span>
          </div>

          <div className="space-y-2.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#FF3E00]"></span>
                <span className="text-white font-bold">CRITICAL</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[#888]">{metrics.criticalCount} ocorrência(s)</span>
                <span className="text-[#FF3E00] font-bold">× 25 pts</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#FF7A00]"></span>
                <span className="text-white font-bold">HIGH</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[#888]">{metrics.highCount} ocorrência(s)</span>
                <span className="text-[#FF7A00] font-bold">× 14 pts</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#EAB308]"></span>
                <span className="text-white font-bold">MEDIUM</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[#888]">{metrics.mediumCount} ocorrência(s)</span>
                <span className="text-[#EAB308] font-bold">× 7 pts</span>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-[#3366FF]"></span>
                <span className="text-white font-bold">LOW</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[#888]">{metrics.lowCount} ocorrência(s)</span>
                <span className="text-[#3366FF] font-bold">× 3 pts</span>
              </div>
            </div>
          </div>
        </div>

        {/* Dimension 2: File Criticality Multipliers */}
        <div className="bg-[#0D0D0D] border border-[#1F1F1F] p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#1A1A1A]">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#3366FF]" />
              <span className="text-xs font-black tracking-wider text-white uppercase">2. Criticidade de Arquivo</span>
            </div>
            <span className="text-[10px] font-mono text-[#666]">Multiplicador</span>
          </div>

          <div className="space-y-2.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <Server className="w-3.5 h-3.5 text-[#FF3E00]" />
                <span className="text-white font-bold">Infra & Configs</span>
              </div>
              <span className="text-[#FF3E00] font-bold">2.0× Multiplier</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] pl-5 -mt-1">
              .env, Docker, cloudConfig, certificados, server.ts
            </p>

            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-[#FF7A00]" />
                <span className="text-white font-bold">Backend & Auth</span>
              </div>
              <span className="text-[#FF7A00] font-bold">1.5× Multiplier</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] pl-5 -mt-1">
              services/, controllers/, routes/, authService
            </p>

            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <Code2 className="w-3.5 h-3.5 text-[#EAB308]" />
                <span className="text-white font-bold">Client & UI</span>
              </div>
              <span className="text-[#EAB308] font-bold">1.0× Multiplier</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] pl-5 -mt-1">
              components/, views/, SDK wrappers públicos
            </p>

            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <TestTube2 className="w-3.5 h-3.5 text-[#3366FF]" />
                <span className="text-white font-bold">Testes & Mocks</span>
              </div>
              <span className="text-[#3366FF] font-bold">0.5× Multiplier</span>
            </div>
            <p className="text-[10px] font-mono text-[#777] pl-5 -mt-1">
              *.test.ts, fixtures/, mocks/, documentação
            </p>
          </div>
        </div>

        {/* Formula & Explainability Callout */}
        <div className="bg-[#0D0D0D] border border-[#1F1F1F] p-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-[#1A1A1A]">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-[#00FF41]" />
                <span className="text-xs font-black tracking-wider text-white uppercase">Fórmula de Cálculo</span>
              </div>
              <span className="text-[10px] font-mono text-[#00FF41]">CURVA SIGMOIDAL</span>
            </div>

            <div className="bg-[#141414] border border-[#2A2A2A] p-3 font-mono text-[11px] text-[#DDD] space-y-1.5">
              <div className="text-[#888]">// Cálculo Ponderado do Score:</div>
              <div className="text-[#00FF41] font-bold">
                Impact_Score = 100 × (1 - e^(-R / 55))
              </div>
              <div className="text-[10px] text-[#888] pt-1 border-t border-[#222]">
                Onde <span className="text-white font-bold">R</span> = Σ (Severidade_i × Criticidade_Arquivo_i)
              </div>
            </div>

            <p className="text-[11px] font-mono text-[#888] leading-relaxed">
              Evita distorções de escala linear: uma credencial em infraestrutura crítica (.env ou config) eleva imediatamente o índice para zona de alto impacto.
            </p>
          </div>

          <div className="pt-2">
            <button
              onClick={() => onNavigateToTab?.('scanner')}
              className="w-full py-2.5 px-3 bg-[#171717] hover:bg-white hover:text-black text-white text-xs font-mono font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 border border-[#333]"
            >
              <span>Auditar no Inspetor de Código</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Ranked File Risk Exposure Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-[#FF3E00]" />
            <h3 className="text-xs font-black tracking-[0.2em] text-white uppercase">
              Ranking de Arquivos por Exposição de Impacto Ponderado
            </h3>
          </div>
          <span className="text-[10px] font-mono text-[#777]">
            {rankedFiles.length} arquivo(s) vulnerável(is) identificado(s)
          </span>
        </div>

        {rankedFiles.length === 0 ? (
          <div className="bg-[#0D0D0D] border border-[#222] p-8 text-center space-y-2">
            <div className="text-sm font-mono text-[#00FF41] font-bold uppercase">
              NENHUMA VULNERABILIDADE DETECTADA
            </div>
            <p className="text-xs font-mono text-[#666]">
              Todos os arquivos analisados estão em conformidade e sem vazamento de segredos.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto border border-[#222] bg-[#0A0A0A]">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#111] text-[#777] uppercase text-[10px] tracking-wider border-b border-[#222]">
                <tr>
                  <th className="py-3 px-4">Arquivo Alvo</th>
                  <th className="py-3 px-4">Criticidade do Arquivo</th>
                  <th className="py-3 px-4">Distribuição de Falhas</th>
                  <th className="py-3 px-4 text-right">Risco Ponderado</th>
                  <th className="py-3 px-4 text-center">Ação</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A]">
                {rankedFiles.map((item, idx) => (
                  <tr key={item.file} className="hover:bg-[#121212] transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-bold text-white flex items-center gap-2">
                        <span className="text-[#555] text-[10px] w-4">{idx + 1}.</span>
                        <span>{item.file}</span>
                      </div>
                      <div className="text-[10px] text-[#666] pl-6 mt-0.5">
                        {item.reason}
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      {getCriticalityBadge(item.criticality, item.multiplier)}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-[10px]">
                        {item.criticalCount > 0 && (
                          <span className="bg-[#220700] text-[#FF3E00] border border-[#FF3E00]/40 px-1.5 py-0.5 font-bold">
                            {item.criticalCount} CRIT
                          </span>
                        )}
                        {item.highCount > 0 && (
                          <span className="bg-[#241200] text-[#FF7A00] border border-[#FF7A00]/40 px-1.5 py-0.5 font-bold">
                            {item.highCount} HIGH
                          </span>
                        )}
                        {item.mediumCount > 0 && (
                          <span className="bg-[#241F00] text-[#EAB308] border border-[#EAB308]/40 px-1.5 py-0.5 font-bold">
                            {item.mediumCount} MED
                          </span>
                        )}
                        {item.lowCount > 0 && (
                          <span className="bg-[#0A162B] text-[#3366FF] border border-[#3366FF]/40 px-1.5 py-0.5 font-bold">
                            {item.lowCount} LOW
                          </span>
                        )}
                        <span className="text-[#666] ml-1">({item.totalFindings} total)</span>
                      </div>
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <span className="text-white font-bold text-sm">
                        {item.totalRiskPoints.toFixed(1)}
                      </span>
                      <span className="text-[#777] text-[10px] ml-1">pts</span>
                    </td>

                    <td className="py-3 px-4 text-center whitespace-nowrap">
                      <button
                        onClick={() => {
                          onNavigateToFile?.(item.file);
                          onNavigateToTab?.('scanner');
                        }}
                        className="px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider bg-[#1A1A1A] hover:bg-white hover:text-black text-white border border-[#333] transition-colors"
                      >
                        Inspecionar
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
