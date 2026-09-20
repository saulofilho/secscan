import React, { useState, useMemo } from 'react';
import { 
  Package, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  ExternalLink, 
  Search, 
  Download, 
  Layers, 
  ArrowUpRight,
  Sparkles,
  FileCode2,
  Copy,
  Check
} from 'lucide-react';
import { ScannedFile } from '../types';
import { scanSoftwareCompositionAnalysis, DependencyPackage, ScaVulnerability } from '../lib/scaScanner';

interface ScaSecurityViewProps {
  files: ScannedFile[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
}

export const ScaSecurityView: React.FC<ScaSecurityViewProps> = ({ files, onNavigateToFile }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | 'VULNERABLE' | 'CRITICAL_HIGH' | 'LICENSE_RISK'>('ALL');
  const [selectedPkg, setSelectedPkg] = useState<DependencyPackage | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const report = useMemo(() => {
    return scanSoftwareCompositionAnalysis(files);
  }, [files]);

  const filteredPackages = useMemo(() => {
    return report.packages.filter(pkg => {
      // Search term
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const matchesName = pkg.name.toLowerCase().includes(term);
        const matchesLicense = pkg.license.toLowerCase().includes(term);
        const matchesVuln = pkg.vulnerabilities.some(v => v.cveId.toLowerCase().includes(term) || v.title.toLowerCase().includes(term));
        if (!matchesName && !matchesLicense && !matchesVuln) return false;
      }

      // Filter modes
      if (filterSeverity === 'VULNERABLE') {
        return pkg.vulnerabilities.length > 0;
      }
      if (filterSeverity === 'CRITICAL_HIGH') {
        return pkg.vulnerabilities.some(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');
      }
      if (filterSeverity === 'LICENSE_RISK') {
        return pkg.licenseRisk === 'HIGH_RISK' || pkg.licenseRisk === 'MEDIUM_RISK';
      }

      return true;
    });
  }, [report, searchTerm, filterSeverity]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `sca-dependency-audit-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header Title & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              <Package className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase font-mono">
              SCA &amp; Auditoria de Dependências
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 font-bold">
              Software Composition Analysis
            </span>
          </div>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Varredura automática de manifestos (package.json, requirements.txt) contra bases públicas OSV, CVE e NVD.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            className="h-8 px-3 rounded inline-flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider text-zinc-300 hover:text-white bg-[#141414] hover:bg-[#222] border border-[#333] transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Exportar SCA (JSON)</span>
          </button>
        </div>
      </div>

      {/* Metrics Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl">
          <span className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider block">Total de Pacotes</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold font-mono text-white">{report.totalDependencies}</span>
            <span className="text-[10px] text-zinc-500 font-mono">({report.manifestsFound.length} manifestos)</span>
          </div>
        </div>

        <div className="bg-[#0C0C0C] border border-rose-900/30 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-rose-400 uppercase tracking-wider block">Vulnerabilidades Críticas</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold font-mono text-rose-500">{report.criticalCount}</span>
            <span className="text-[10px] text-rose-400/70 font-mono">CVEs CVSS &gt;= 9.0</span>
          </div>
        </div>

        <div className="bg-[#0C0C0C] border border-amber-900/30 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-amber-400 uppercase tracking-wider block">Pacotes Afetados</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold font-mono text-amber-500">{report.vulnerableCount}</span>
            <span className="text-[10px] text-amber-400/70 font-mono">com patches pendentes</span>
          </div>
        </div>

        <div className="bg-[#0C0C0C] border border-purple-900/30 p-4 rounded-xl">
          <span className="text-[11px] font-mono text-purple-400 uppercase tracking-wider block">Risco de Licença (Copyleft)</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold font-mono text-purple-400">{report.copyleftRiskCount}</span>
            <span className="text-[10px] text-purple-300/70 font-mono">GPL/AGPL viral</span>
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#0D0D0D] border border-[#222] p-3 rounded-xl flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Buscar por pacote, CVE ou licença..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-black/60 border border-[#2A2A2A] focus:border-cyan-500 rounded-lg text-xs font-mono text-white placeholder-zinc-500 focus:outline-none transition-colors"
          />
        </div>

        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={() => setFilterSeverity('ALL')}
            className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer border ${
              filterSeverity === 'ALL'
                ? 'bg-zinc-800 text-white border-zinc-600'
                : 'bg-transparent text-zinc-400 border-transparent hover:text-white'
            }`}
          >
            Todos ({report.packages.length})
          </button>
          <button
            onClick={() => setFilterSeverity('VULNERABLE')}
            className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer border ${
              filterSeverity === 'VULNERABLE'
                ? 'bg-amber-950 text-amber-200 border-amber-600'
                : 'bg-transparent text-zinc-400 border-transparent hover:text-amber-300'
            }`}
          >
            Vulneráveis ({report.vulnerableCount})
          </button>
          <button
            onClick={() => setFilterSeverity('CRITICAL_HIGH')}
            className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer border ${
              filterSeverity === 'CRITICAL_HIGH'
                ? 'bg-rose-950 text-rose-200 border-rose-600'
                : 'bg-transparent text-zinc-400 border-transparent hover:text-rose-300'
            }`}
          >
            Críticos &amp; Altos ({report.criticalCount + report.highCount})
          </button>
          <button
            onClick={() => setFilterSeverity('LICENSE_RISK')}
            className={`px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer border ${
              filterSeverity === 'LICENSE_RISK'
                ? 'bg-purple-950 text-purple-200 border-purple-600'
                : 'bg-transparent text-zinc-400 border-transparent hover:text-purple-300'
            }`}
          >
            Copyleft / Licença ({report.copyleftRiskCount})
          </button>
        </div>
      </div>

      {/* Main Packages Table & Details Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Package List (Left 2 cols) */}
        <div className="lg:col-span-2 space-y-3">
          {filteredPackages.length === 0 ? (
            <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl font-mono text-xs text-zinc-500">
              Nenhuma dependência encontrada para os filtros selecionados.
            </div>
          ) : (
            filteredPackages.map(pkg => {
              const hasVuln = pkg.vulnerabilities.length > 0;
              const hasCritical = pkg.vulnerabilities.some(v => v.severity === 'CRITICAL');
              const isSelected = selectedPkg?.id === pkg.id;

              return (
                <div
                  key={pkg.id}
                  onClick={() => setSelectedPkg(pkg)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-[#141414] border-cyan-500 shadow-md ring-1 ring-cyan-500/30'
                      : hasCritical
                      ? 'bg-[#0E0708] border-rose-900/40 hover:border-rose-600'
                      : hasVuln
                      ? 'bg-[#0E0B07] border-amber-900/40 hover:border-amber-600'
                      : 'bg-[#0A0A0A] border-[#222] hover:border-[#333]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-sm text-white">{pkg.name}</span>
                        <span className="font-mono text-xs text-zinc-400">v{pkg.version}</span>
                        <span className="text-[9.5px] font-mono px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                          {pkg.type}
                        </span>
                        <span
                          className={`text-[9.5px] font-mono px-1.5 py-0.2 rounded font-bold ${
                            pkg.licenseRisk === 'HIGH_RISK'
                              ? 'bg-purple-950 text-purple-300 border border-purple-800'
                              : 'bg-zinc-800 text-emerald-400 border border-zinc-700'
                          }`}
                        >
                          {pkg.license}
                        </span>
                      </div>
                      <p className="text-[11px] font-mono text-zinc-500 mt-1">
                        Detectado em: {pkg.manifestFile}
                      </p>
                    </div>

                    <div className="text-right shrink-0">
                      {hasVuln ? (
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                          hasCritical ? 'bg-rose-600 text-white animate-pulse' : 'bg-amber-600 text-white'
                        }`}>
                          {pkg.vulnerabilities.length} CVE{pkg.vulnerabilities.length > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-emerald-400">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>Seguro</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Vulnerabilities Pill Preview */}
                  {hasVuln && (
                    <div className="mt-3 pt-3 border-t border-white/5 flex flex-wrap gap-2">
                      {pkg.vulnerabilities.map(v => (
                        <span
                          key={v.id}
                          className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/50 border border-rose-900/50 text-rose-300 inline-flex items-center gap-1"
                        >
                          <span className="font-bold">{v.cveId}</span>
                          <span className="text-zinc-500">|</span>
                          <span>CVSS {v.cvssScore}</span>
                        </span>
                      ))}
                      {pkg.recommendedVersion && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-800/40 text-emerald-300 ml-auto inline-flex items-center gap-1">
                          <Sparkles className="w-2.5 h-2.5 text-emerald-400" />
                          <span>Atualizar para {pkg.recommendedVersion}</span>
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Selected Package Details Panel (Right 1 col) */}
        <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 sticky top-20 space-y-4">
          {selectedPkg ? (
            <>
              <div className="flex items-start justify-between gap-2 border-b border-[#222] pb-3">
                <div>
                  <h3 className="font-mono font-bold text-base text-white">{selectedPkg.name}</h3>
                  <span className="text-xs font-mono text-zinc-400">Versão instalada: {selectedPkg.version}</span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                  {selectedPkg.type}
                </span>
              </div>

              {/* License Compliance Section */}
              <div className="space-y-1 font-mono text-xs">
                <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">Conformidade de Licença:</span>
                <div className={`p-2.5 rounded-lg border text-xs ${
                  selectedPkg.licenseRisk === 'HIGH_RISK'
                    ? 'bg-purple-950/30 border-purple-800 text-purple-200'
                    : 'bg-zinc-900/50 border-zinc-800 text-zinc-300'
                }`}>
                  <div className="flex items-center justify-between font-bold">
                    <span>{selectedPkg.license}</span>
                    <span className="text-[10px]">{selectedPkg.licenseRisk}</span>
                  </div>
                  <p className="text-[11px] text-zinc-400 mt-1 leading-relaxed">
                    {selectedPkg.licenseExplanation}
                  </p>
                </div>
              </div>

              {/* Vulnerabilities Detail */}
              <div className="space-y-2">
                <span className="text-[10px] font-mono font-bold text-zinc-400 uppercase tracking-wider">
                  Vulnerabilidades Detectadas ({selectedPkg.vulnerabilities.length}):
                </span>

                {selectedPkg.vulnerabilities.length === 0 ? (
                  <div className="p-3 bg-emerald-950/20 border border-emerald-900/30 rounded-lg text-emerald-400 font-mono text-xs flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    <span>Nenhuma vulnerabilidade conhecida para esta versão.</span>
                  </div>
                ) : (
                  selectedPkg.vulnerabilities.map(vuln => (
                    <div key={vuln.id} className="p-3 bg-black/60 border border-rose-900/40 rounded-lg space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-rose-400">{vuln.cveId}</span>
                        <span className="px-1.5 py-0.2 rounded bg-rose-900 text-white font-bold text-[9px]">
                          CVSS {vuln.cvssScore} ({vuln.severity})
                        </span>
                      </div>
                      <p className="font-semibold text-zinc-200 text-[11px]">{vuln.title}</p>
                      <p className="text-[10.5px] text-zinc-400 leading-relaxed">{vuln.description}</p>
                      <div className="flex items-center justify-between pt-1 text-[10px] text-zinc-500 border-t border-white/5">
                        <span>Afeta: {vuln.vulnerableVersions}</span>
                        <span className="text-emerald-400 font-bold">Correção: &gt;= {vuln.fixedVersion}</span>
                      </div>
                      {vuln.references.length > 0 && (
                        <a
                          href={vuln.references[0]}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-[10px] text-cyan-400 hover:underline pt-1"
                        >
                          <ExternalLink className="w-2.5 h-2.5" />
                          <span>Ver NVD / Advisory Oficial</span>
                        </a>
                      )}
                    </div>
                  ))
                )}
              </div>

              {/* Remediation Action Button */}
              {selectedPkg.recommendedVersion && (
                <div className="pt-2">
                  <button
                    onClick={() => {
                      if (onNavigateToFile) {
                        onNavigateToFile(selectedPkg.manifestFile, 1);
                      }
                    }}
                    className="w-full py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-sm"
                  >
                    <FileCode2 className="w-3.5 h-3.5" />
                    <span>Abrir {selectedPkg.manifestFile} para Atualizar</span>
                  </button>
                </div>
              )}
            </>
          ) : (
            <div className="p-6 text-center font-mono text-xs text-zinc-500 space-y-2">
              <Package className="w-8 h-8 text-zinc-700 mx-auto" />
              <p>Selecione um pacote na lista para visualizar o dossiê detalhado de CVEs, histórico de versões e riscos de licenciamento.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
