import React, { useState, useMemo } from 'react';
import { 
  Server, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Container, 
  FileCode2, 
  Download, 
  Layers,
  Terminal,
  ExternalLink,
  ChevronRight,
  Sparkles
} from 'lucide-react';
import { ScannedFile } from '../types';
import { scanInfrastructureAsCode, IacFinding, IacReport } from '../lib/iacScanner';

interface IacSecurityViewProps {
  files: ScannedFile[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
}

export const IacSecurityView: React.FC<IacSecurityViewProps> = ({ files, onNavigateToFile }) => {
  const [selectedCategory, setSelectedCategory] = useState<'ALL' | 'DOCKER' | 'KUBERNETES' | 'COMPOSE' | 'CICD' | 'TERRAFORM'>('ALL');
  const [selectedFinding, setSelectedFinding] = useState<IacFinding | null>(null);

  const report: IacReport = useMemo(() => {
    return scanInfrastructureAsCode(files);
  }, [files]);

  const filteredFindings = useMemo(() => {
    if (selectedCategory === 'ALL') return report.findings;
    return report.findings.filter(f => f.category === selectedCategory);
  }, [report, selectedCategory]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/30">
              <Container className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase font-mono">
              IaC Security &amp; Misconfigurations
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-950/60 text-orange-300 border border-orange-800/60 font-bold">
              Docker / K8s / Terraform / CI-CD
            </span>
          </div>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Auditoria estática de configurações de containers, orquestração Kubernetes, compose e pipelines contra CIS Benchmarks.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="px-4 py-2 rounded-xl bg-[#0F0F0F] border border-[#222] flex items-center gap-3 font-mono">
            <div className="text-right">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">IaC Posture Score</span>
              <span className={`text-lg font-bold ${
                report.iacPostureScore >= 80 ? 'text-emerald-400' : report.iacPostureScore >= 50 ? 'text-amber-400' : 'text-rose-500'
              }`}>
                {report.iacPostureScore}/100
              </span>
            </div>
            <div className="w-9 h-9 rounded-full border-2 flex items-center justify-center font-bold text-xs border-current"
                 style={{ color: report.iacPostureScore >= 80 ? '#34d399' : report.iacPostureScore >= 50 ? '#fbbf24' : '#f43f5e' }}>
              {report.iacPostureScore}%
            </div>
          </div>
        </div>
      </div>

      {/* Summary Tech Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 font-mono">
        <button
          onClick={() => setSelectedCategory('DOCKER')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
            selectedCategory === 'DOCKER' ? 'bg-[#181818] border-orange-500 shadow' : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
          }`}
        >
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Docker</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-xl font-bold text-white">{report.summaryByTech.DOCKER.count}</span>
            <span className="text-[10px] text-rose-400 font-semibold">{report.summaryByTech.DOCKER.critical} crít.</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedCategory('KUBERNETES')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
            selectedCategory === 'KUBERNETES' ? 'bg-[#181818] border-orange-500 shadow' : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
          }`}
        >
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Kubernetes</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-xl font-bold text-white">{report.summaryByTech.KUBERNETES.count}</span>
            <span className="text-[10px] text-rose-400 font-semibold">{report.summaryByTech.KUBERNETES.critical} crít.</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedCategory('COMPOSE')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
            selectedCategory === 'COMPOSE' ? 'bg-[#181818] border-orange-500 shadow' : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
          }`}
        >
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Compose</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-xl font-bold text-white">{report.summaryByTech.COMPOSE.count}</span>
            <span className="text-[10px] text-rose-400 font-semibold">{report.summaryByTech.COMPOSE.critical} crít.</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedCategory('CICD')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
            selectedCategory === 'CICD' ? 'bg-[#181818] border-orange-500 shadow' : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
          }`}
        >
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">CI/CD Workflows</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-xl font-bold text-white">{report.summaryByTech.CICD.count}</span>
            <span className="text-[10px] text-rose-400 font-semibold">{report.summaryByTech.CICD.critical} crít.</span>
          </div>
        </button>

        <button
          onClick={() => setSelectedCategory('ALL')}
          className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
            selectedCategory === 'ALL' ? 'bg-[#181818] border-orange-500 shadow' : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
          }`}
        >
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Todas Categorias</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-xl font-bold text-white">{report.findings.length}</span>
            <span className="text-[10px] text-zinc-500">desvios</span>
          </div>
        </button>
      </div>

      {/* Main Content: Findings and Details */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Finding List (Left 2 cols) */}
        <div className="lg:col-span-2 space-y-3">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl font-mono text-xs text-zinc-500">
              Nenhuma inconformidade de infraestrutura encontrada para esta categoria.
            </div>
          ) : (
            filteredFindings.map(finding => {
              const isSelected = selectedFinding?.id === finding.id;
              const isCritical = finding.severity === 'CRITICAL';

              return (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-[#141414] border-orange-500 shadow-md ring-1 ring-orange-500/30'
                      : isCritical
                      ? 'bg-[#0E0708] border-rose-900/40 hover:border-rose-600'
                      : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3 font-mono">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold uppercase tracking-wider ${
                          finding.severity === 'CRITICAL' 
                            ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                            : finding.severity === 'HIGH'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-blue-950 text-blue-300 border border-blue-800'
                        }`}>
                          {finding.severity}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300 font-bold">
                          {finding.category}
                        </span>
                        <span className="text-[10px] text-zinc-500">{finding.ruleId}</span>
                        {finding.compliance?.cisBenchmark && (
                          <span className="text-[9.5px] px-1.5 py-0.2 rounded bg-zinc-900 text-zinc-400 border border-zinc-700">
                            {finding.compliance.cisBenchmark}
                          </span>
                        )}
                      </div>
                      <h3 className="font-bold text-sm text-zinc-100">{finding.title}</h3>
                      <p className="text-[11px] text-zinc-400 leading-relaxed">{finding.description}</p>
                    </div>

                    <ChevronRight className={`w-4 h-4 shrink-0 transition-transform ${isSelected ? 'rotate-90 text-orange-400' : 'text-zinc-600'}`} />
                  </div>

                  {/* Snippet Line Preview */}
                  <div className="mt-3 pt-2.5 border-t border-white/5 flex items-center justify-between font-mono text-[11px]">
                    <div className="flex items-center gap-2 text-zinc-500 truncate">
                      <FileCode2 className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
                      <span className="truncate">{finding.file}:{finding.line}</span>
                    </div>
                    <code className="text-[10.5px] bg-black/60 px-2 py-0.5 rounded text-orange-300/90 border border-white/5 max-w-[280px] truncate">
                      {finding.snippet}
                    </code>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Selected Finding Detail Drawer (Right 1 col) */}
        <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 sticky top-20 space-y-4 font-mono">
          {selectedFinding ? (
            <>
              <div className="border-b border-[#222] pb-3 space-y-1">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-800">
                    {selectedFinding.category}
                  </span>
                  <span className="text-xs text-zinc-500">{selectedFinding.ruleId}</span>
                </div>
                <h3 className="font-bold text-sm text-white">{selectedFinding.title}</h3>
                <span className="text-[11px] text-zinc-400 block">{selectedFinding.file}:{selectedFinding.line}</span>
              </div>

              {/* Code Snippet Box */}
              <div className="space-y-1 text-xs">
                <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">Trecho Inseguro:</span>
                <div className="p-3 bg-black rounded-lg border border-rose-900/40 text-rose-300 overflow-x-auto text-[11px]">
                  <code>{selectedFinding.snippet}</code>
                </div>
              </div>

              {/* Remediation Guide */}
              <div className="space-y-1 text-xs">
                <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">Remediação Recomendada:</span>
                <div className="p-3 bg-zinc-900/60 rounded-lg border border-zinc-800 text-zinc-300 text-[11px] leading-relaxed">
                  {selectedFinding.remediation}
                </div>
              </div>

              {/* Compliance Badges */}
              {selectedFinding.compliance && (
                <div className="space-y-1 text-xs">
                  <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">Normas de Conformidade:</span>
                  <div className="flex flex-wrap gap-2 text-[10px]">
                    {selectedFinding.compliance.cisBenchmark && (
                      <span className="px-2 py-1 rounded bg-zinc-800 text-zinc-200 border border-zinc-700">
                        {selectedFinding.compliance.cisBenchmark}
                      </span>
                    )}
                    {selectedFinding.compliance.nist && (
                      <span className="px-2 py-1 rounded bg-zinc-800 text-zinc-200 border border-zinc-700">
                        {selectedFinding.compliance.nist}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Action: Open File */}
              <div className="pt-2">
                <button
                  onClick={() => {
                    if (onNavigateToFile) {
                      onNavigateToFile(selectedFinding.file, selectedFinding.line);
                    }
                  }}
                  className="w-full py-2 px-3 rounded-lg bg-orange-600 hover:bg-orange-500 text-white text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-colors cursor-pointer"
                >
                  <FileCode2 className="w-3.5 h-3.5" />
                  <span>Navegar para {selectedFinding.file}</span>
                </button>
              </div>
            </>
          ) : (
            <div className="p-6 text-center text-xs text-zinc-500 space-y-2">
              <Container className="w-8 h-8 text-zinc-700 mx-auto" />
              <p>Selecione uma vulnerabilidade de IaC na lista para inspecionar os detalhes técnicos e conformidade com CIS Benchmarks.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
