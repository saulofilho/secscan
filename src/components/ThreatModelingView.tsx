import React, { useState, useMemo } from 'react';
import { 
  Target, 
  ShieldAlert, 
  Calculator, 
  CheckCircle2, 
  AlertTriangle, 
  Compass, 
  Copy, 
  Check, 
  Sliders, 
  ExternalLink,
  Layers,
  ArrowRight
} from 'lucide-react';
import { ScanFinding, ApiEndpointFinding } from '../types';
import { 
  buildThreatModelFromWorkspace, 
  calculateCvssScore, 
  CvssMetrics, 
  StrideCategory 
} from '../lib/threatModeler';

interface ThreatModelingViewProps {
  findings: ScanFinding[];
  endpoints: ApiEndpointFinding[];
}

export const ThreatModelingView: React.FC<ThreatModelingViewProps> = ({ findings, endpoints }) => {
  const [activeTab, setActiveTab] = useState<'STRIDE' | 'ASVS' | 'CVSS_CALCULATOR'>('STRIDE');
  const [strideFilter, setStrideFilter] = useState<StrideCategory | 'ALL'>('ALL');
  const [copiedVector, setCopiedVector] = useState(false);

  // Threat Model & ASVS Data
  const { strideThreats, asvsRequirements, compliancePercentage } = useMemo(() => {
    return buildThreatModelFromWorkspace(findings, endpoints);
  }, [findings, endpoints]);

  // CVSS Calculator State
  const [cvssMetrics, setCvssMetrics] = useState<CvssMetrics>({
    attackVector: 'NETWORK',
    attackComplexity: 'LOW',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    scope: 'UNCHANGED',
    confidentiality: 'HIGH',
    integrity: 'HIGH',
    availability: 'HIGH'
  });

  const cvssResult = useMemo(() => {
    return calculateCvssScore(cvssMetrics);
  }, [cvssMetrics]);

  const filteredStrideThreats = useMemo(() => {
    if (strideFilter === 'ALL') return strideThreats;
    return strideThreats.filter(t => t.category === strideFilter);
  }, [strideThreats, strideFilter]);

  const handleCopyVector = () => {
    navigator.clipboard.writeText(cvssResult.vectorString);
    setCopiedVector(true);
    setTimeout(() => setCopiedVector(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono">
      {/* Header & Sub-Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-teal-500/10 text-teal-400 border border-teal-500/30">
              <Target className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase">
              Modelagem de Ameaças &amp; Matriz STRIDE
            </h1>
            <span className="text-[10px] px-2 py-0.5 rounded bg-teal-950/60 text-teal-300 border border-teal-800/60 font-bold">
              STRIDE / OWASP ASVS / CVSS v3.1
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Mapeamento sistemático de superfície de ataque, verificação de conformidade ASVS e calculadora oficial de severidade CVSS.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('STRIDE')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeTab === 'STRIDE'
                ? 'bg-teal-600 text-white border-teal-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            Matriz STRIDE ({strideThreats.length})
          </button>
          <button
            onClick={() => setActiveTab('ASVS')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeTab === 'ASVS'
                ? 'bg-teal-600 text-white border-teal-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            OWASP ASVS ({compliancePercentage}%)
          </button>
          <button
            onClick={() => setActiveTab('CVSS_CALCULATOR')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeTab === 'CVSS_CALCULATOR'
                ? 'bg-teal-600 text-white border-teal-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            Calculadora CVSS v3.1 ({cvssResult.baseScore})
          </button>
        </div>
      </div>

      {/* TAB 1: STRIDE MATRIX */}
      {activeTab === 'STRIDE' && (
        <div className="space-y-5">
          {/* Category Filter Pills */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
            <button
              onClick={() => setStrideFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg font-bold border transition-colors cursor-pointer ${
                strideFilter === 'ALL' ? 'bg-zinc-800 text-white border-zinc-600' : 'bg-[#0F0F0F] text-zinc-400 border-[#222] hover:text-white'
              }`}
            >
              Todas Ameaças ({strideThreats.length})
            </button>
            {(['SPOOFING', 'TAMPERING', 'REPUDIATION', 'INFORMATION_DISCLOSURE', 'DENIAL_OF_SERVICE', 'ELEVATION_OF_PRIVILEGE'] as StrideCategory[]).map(cat => {
              const count = strideThreats.filter(t => t.category === cat).length;
              return (
                <button
                  key={cat}
                  onClick={() => setStrideFilter(cat)}
                  className={`px-3 py-1.5 rounded-lg font-bold border transition-colors cursor-pointer whitespace-nowrap ${
                    strideFilter === cat ? 'bg-teal-950 text-teal-200 border-teal-600 shadow' : 'bg-[#0F0F0F] text-zinc-400 border-[#222] hover:text-teal-300'
                  }`}
                >
                  {cat} ({count})
                </button>
              );
            })}
          </div>

          {/* Threats List */}
          <div className="space-y-3">
            {filteredStrideThreats.length === 0 ? (
              <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500">
                Nenhuma ameaça mapeada nesta categoria STRIDE.
              </div>
            ) : (
              filteredStrideThreats.map(threat => (
                <div
                  key={threat.id}
                  className="p-4 bg-[#0A0A0A] border border-[#222] hover:border-teal-500/40 rounded-xl space-y-2.5 transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="px-2 py-0.2 rounded text-[10px] font-bold bg-teal-950 text-teal-300 border border-teal-800">
                          {threat.category}
                        </span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                          threat.riskLevel === 'CRITICAL' ? 'bg-rose-950 text-rose-300' : 'bg-amber-950 text-amber-300'
                        }`}>
                          {threat.riskLevel}
                        </span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                          threat.mitigationStatus === 'UNMITIGATED'
                            ? 'bg-rose-900/60 text-rose-200'
                            : threat.mitigationStatus === 'PARTIALLY_MITIGATED'
                            ? 'bg-amber-900/60 text-amber-200'
                            : 'bg-emerald-900/60 text-emerald-200'
                        }`}>
                          {threat.mitigationStatus}
                        </span>
                      </div>
                      <h3 className="font-bold text-sm text-white">{threat.title}</h3>
                      <p className="text-xs text-zinc-400 leading-relaxed">{threat.threatDescription}</p>
                    </div>

                    <div className="text-right text-[10px] text-zinc-500 shrink-0">
                      <span>Ativo Afetado:</span>
                      <code className="block text-zinc-300 font-bold">{threat.affectedAsset}</code>
                    </div>
                  </div>

                  <div className="p-2.5 bg-zinc-900/60 border border-zinc-800 rounded-lg text-xs space-y-1">
                    <span className="text-[10px] font-bold text-teal-400 uppercase tracking-wider block">
                      Contramedida Recomendada:
                    </span>
                    <p className="text-[11px] text-zinc-300 leading-relaxed">{threat.recommendedCountermeasure}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* TAB 2: OWASP ASVS MATRIX */}
      {activeTab === 'ASVS' && (
        <div className="space-y-6">
          <div className="bg-[#0C0C0C] border border-[#222] p-5 rounded-xl flex items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">Nível de Maturidade OWASP</span>
              <h2 className="text-xl font-bold text-white">OWASP Application Security Verification Standard v4.0.3</h2>
              <p className="text-xs text-zinc-400">Verificação de conformidade em arquitetura, autenticação, controle de acesso e criptografia.</p>
            </div>
            <div className="text-right">
              <span className="text-2xl font-bold text-teal-400">{compliancePercentage}%</span>
              <span className="text-[10px] text-zinc-500 block">Conforme</span>
            </div>
          </div>

          <div className="space-y-3">
            {asvsRequirements.map(req => {
              const isCompliant = req.status === 'COMPLIANT';
              const isNonCompliant = req.status === 'NON_COMPLIANT';

              return (
                <div
                  key={req.chapterId}
                  className={`p-4 rounded-xl border ${
                    isCompliant ? 'bg-[#070E0A] border-emerald-900/40' : isNonCompliant ? 'bg-[#0E0708] border-rose-900/40' : 'bg-[#0E0B07] border-amber-900/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.2 rounded text-[10px] font-bold bg-zinc-800 text-zinc-300">
                          {req.chapterId} ({req.level})
                        </span>
                        <h3 className="font-bold text-sm text-white">{req.chapterName}</h3>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                          isCompliant ? 'bg-emerald-900 text-emerald-200' : isNonCompliant ? 'bg-rose-900 text-rose-200' : 'bg-amber-900 text-amber-200'
                        }`}>
                          {req.status}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400">{req.description}</p>
                    </div>

                    <span className="text-[10px] text-zinc-500 shrink-0">
                      {req.findingCount} achado{req.findingCount !== 1 ? 's' : ''} associado{req.findingCount !== 1 ? 's' : ''}
                    </span>
                  </div>

                  <div className="mt-3 pt-2.5 border-t border-white/5 text-[11px] text-teal-400/90">
                    <span className="text-zinc-500">Diretriz de Verificação: </span>
                    {req.verificationGuidance}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 3: CVSS V3.1 CALCULATOR */}
      {activeTab === 'CVSS_CALCULATOR' && (
        <div className="space-y-6">
          {/* Result Score Banner */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">
                FIRST.org CVSS v3.1 Base Score Calculator
              </span>
              <div className="flex items-center gap-3">
                <span className="text-4xl font-bold text-white">{cvssResult.baseScore}</span>
                <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider ${
                  cvssResult.severityRating === 'CRITICAL' ? 'bg-rose-600 text-white animate-pulse' :
                  cvssResult.severityRating === 'HIGH' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                  cvssResult.severityRating === 'MEDIUM' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                  'bg-emerald-950 text-emerald-300 border border-emerald-800'
                }`}>
                  {cvssResult.severityRating}
                </span>
              </div>
              <div className="flex items-center gap-4 text-xs text-zinc-400 pt-1">
                <span>Impacto: <strong>{cvssResult.impactSubScore}</strong></span>
                <span>Explorabilidade: <strong>{cvssResult.exploitabilitySubScore}</strong></span>
              </div>
            </div>

            <div className="space-y-1.5 sm:text-right">
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">Vector String Padronizada</span>
              <div className="flex items-center gap-2">
                <code className="px-2.5 py-1.5 rounded bg-black border border-white/10 text-teal-300 text-xs truncate max-w-xs sm:max-w-md">
                  {cvssResult.vectorString}
                </code>
                <button
                  onClick={handleCopyVector}
                  className="px-2.5 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs transition-colors cursor-pointer flex items-center gap-1 shrink-0"
                >
                  {copiedVector ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedVector ? 'Copiado' : 'Copiar'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Interactive Metric Controls Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            {/* Attack Vector */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Attack Vector (AV)</span>
              <select
                value={cvssMetrics.attackVector}
                onChange={(e) => setCvssMetrics(m => ({ ...m, attackVector: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="NETWORK">Network (N) - 0.85</option>
                <option value="ADJACENT">Adjacent (A) - 0.62</option>
                <option value="LOCAL">Local (L) - 0.55</option>
                <option value="PHYSICAL">Physical (P) - 0.20</option>
              </select>
            </div>

            {/* Attack Complexity */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Attack Complexity (AC)</span>
              <select
                value={cvssMetrics.attackComplexity}
                onChange={(e) => setCvssMetrics(m => ({ ...m, attackComplexity: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="LOW">Low (L) - 0.77</option>
                <option value="HIGH">High (H) - 0.44</option>
              </select>
            </div>

            {/* Privileges Required */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Privileges Required (PR)</span>
              <select
                value={cvssMetrics.privilegesRequired}
                onChange={(e) => setCvssMetrics(m => ({ ...m, privilegesRequired: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="NONE">None (N) - 0.85</option>
                <option value="LOW">Low (L) - 0.62</option>
                <option value="HIGH">High (H) - 0.27</option>
              </select>
            </div>

            {/* User Interaction */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">User Interaction (UI)</span>
              <select
                value={cvssMetrics.userInteraction}
                onChange={(e) => setCvssMetrics(m => ({ ...m, userInteraction: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="NONE">None (N) - 0.85</option>
                <option value="REQUIRED">Required (R) - 0.62</option>
              </select>
            </div>

            {/* Scope */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Scope (S)</span>
              <select
                value={cvssMetrics.scope}
                onChange={(e) => setCvssMetrics(m => ({ ...m, scope: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="UNCHANGED">Unchanged (U)</option>
                <option value="CHANGED">Changed (C)</option>
              </select>
            </div>

            {/* Confidentiality */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Confidentiality (C)</span>
              <select
                value={cvssMetrics.confidentiality}
                onChange={(e) => setCvssMetrics(m => ({ ...m, confidentiality: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="HIGH">High (H) - 0.56</option>
                <option value="LOW">Low (L) - 0.22</option>
                <option value="NONE">None (N) - 0.00</option>
              </select>
            </div>

            {/* Integrity */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Integrity (I)</span>
              <select
                value={cvssMetrics.integrity}
                onChange={(e) => setCvssMetrics(m => ({ ...m, integrity: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="HIGH">High (H) - 0.56</option>
                <option value="LOW">Low (L) - 0.22</option>
                <option value="NONE">None (N) - 0.00</option>
              </select>
            </div>

            {/* Availability */}
            <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2">
              <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">Availability (A)</span>
              <select
                value={cvssMetrics.availability}
                onChange={(e) => setCvssMetrics(m => ({ ...m, availability: e.target.value as any }))}
                className="w-full bg-black border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-white font-mono focus:outline-none focus:border-teal-500"
              >
                <option value="HIGH">High (H) - 0.56</option>
                <option value="LOW">Low (L) - 0.22</option>
                <option value="NONE">None (N) - 0.00</option>
              </select>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
