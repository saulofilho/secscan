import React, { useState } from 'react';
import {
  Boxes,
  Database,
  KeyRound,
  FileCode,
  AlertTriangle,
  Flame,
  ShieldCheck,
  Copy,
  Check,
  Terminal,
  Download,
  ExternalLink,
  Search,
  Cloud,
  Layers,
  Code2,
  Network,
  ArrowRight
} from 'lucide-react';
import { JsMinerResults, CloudBucketFinding, JwtTokenFinding, BundledDependencyFinding, DangerousSinkFinding, SourceMapFinding } from '../types';

interface JsMinerViewProps {
  jsMiner?: JsMinerResults;
  onNavigateToDataFlow?: () => void;
}

export const JsMinerView: React.FC<JsMinerViewProps> = ({ jsMiner, onNavigateToDataFlow }) => {
  const [activeSubTab, setActiveSubTab] = useState<'BUCKETS' | 'JWTS' | 'SOURCEMAPS' | 'DEPS' | 'SINKS'>('BUCKETS');
  const [searchTerm, setSearchTerm] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const safeMiner: JsMinerResults = jsMiner || {
    sourceMaps: [],
    cloudBuckets: [],
    jwtTokens: [],
    dependencies: [],
    dangerousSinks: [],
    totalAssetsCount: 0
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportJson = () => {
    const json = JSON.stringify(safeMiner, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'js-miner-reconnaissance-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filter lists
  const filteredBuckets = safeMiner.cloudBuckets.filter(b => 
    b.bucketName.toLowerCase().includes(searchTerm.toLowerCase()) ||
    b.provider.toLowerCase().includes(searchTerm.toLowerCase()) ||
    b.file.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredJwts = safeMiner.jwtTokens.filter(j =>
    (j.subject && j.subject.toLowerCase().includes(searchTerm.toLowerCase())) ||
    (j.roles && j.roles.some(r => r.toLowerCase().includes(searchTerm.toLowerCase()))) ||
    j.file.toLowerCase().includes(searchTerm.toLowerCase()) ||
    j.algorithm.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredSourceMaps = safeMiner.sourceMaps.filter(s =>
    s.file.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.url.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredDependencies = safeMiner.dependencies.filter(d =>
    d.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    d.version.toLowerCase().includes(searchTerm.toLowerCase()) ||
    d.file.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredSinks = safeMiner.dangerousSinks.filter(s =>
    s.sinkType.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.file.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Overview Banner */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // PORTSWIGGER JS-MINER ENGINE
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333]">
              {safeMiner.totalAssetsCount} ASSETS IDENTIFIED
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1">
            JS Miner Reconnaissance
          </h1>
          <p className="text-xs font-mono text-[#888] mt-1.5 max-w-3xl leading-relaxed">
            Mapeamento profundo em código JavaScript e bundles compilados inspirado na extensão oficial PortSwigger JS-Miner: descobre Cloud Buckets (S3, GCS, Azure, Firebase), tokens JWT expostos com decodificação de claims, referências a Source Maps (.map), bibliotecas com CVEs e sinks DOM perigosos.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap shrink-0">
          {onNavigateToDataFlow && (
            <button
              onClick={onNavigateToDataFlow}
              className="inline-flex items-center gap-2 px-4 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-[#00E5FF] bg-[#0E1B20] hover:bg-[#00E5FF] hover:text-black border border-[#00E5FF]/40 transition-colors shrink-0"
              title="Mapear fluxo de dados em Grafo D3 interativo"
            >
              <Network className="w-3.5 h-3.5" />
              <span>Grafo de Fluxo D3 (Taint)</span>
            </button>
          )}

          <button
            onClick={handleExportJson}
            className="inline-flex items-center gap-2 px-4 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors shrink-0"
          >
            <Download className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Exportar JS-Miner JSON</span>
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <button
          onClick={() => setActiveSubTab('BUCKETS')}
          className={`p-4 border text-left transition-all ${
            activeSubTab === 'BUCKETS'
              ? 'bg-[#111] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.15)]'
              : 'bg-[#0A0A0A] border-[#1F1F1F] hover:border-[#333]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-[#888]">Cloud Buckets</span>
            <Cloud className="w-4 h-4 text-[#FF3E00]" />
          </div>
          <p className="text-2xl font-black text-white font-mono mt-2">
            {safeMiner.cloudBuckets.length}
          </p>
          <span className="text-[10px] font-mono text-[#666] block mt-0.5">S3, GCS, Azure Blob</span>
        </button>

        <button
          onClick={() => setActiveSubTab('JWTS')}
          className={`p-4 border text-left transition-all ${
            activeSubTab === 'JWTS'
              ? 'bg-[#111] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.15)]'
              : 'bg-[#0A0A0A] border-[#1F1F1F] hover:border-[#333]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-[#888]">Tokens JWT</span>
            <KeyRound className="w-4 h-4 text-[#FF7A00]" />
          </div>
          <p className="text-2xl font-black text-white font-mono mt-2">
            {safeMiner.jwtTokens.length}
          </p>
          <span className="text-[10px] font-mono text-[#666] block mt-0.5">Claims & Assinaturas</span>
        </button>

        <button
          onClick={() => setActiveSubTab('SOURCEMAPS')}
          className={`p-4 border text-left transition-all ${
            activeSubTab === 'SOURCEMAPS'
              ? 'bg-[#111] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.15)]'
              : 'bg-[#0A0A0A] border-[#1F1F1F] hover:border-[#333]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-[#888]">Source Maps</span>
            <FileCode className="w-4 h-4 text-[#00FF41]" />
          </div>
          <p className="text-2xl font-black text-white font-mono mt-2">
            {safeMiner.sourceMaps.length}
          </p>
          <span className="text-[10px] font-mono text-[#666] block mt-0.5">Vazamento de Código</span>
        </button>

        <button
          onClick={() => setActiveSubTab('DEPS')}
          className={`p-4 border text-left transition-all ${
            activeSubTab === 'DEPS'
              ? 'bg-[#111] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.15)]'
              : 'bg-[#0A0A0A] border-[#1F1F1F] hover:border-[#333]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-[#888]">Bibliotecas</span>
            <Layers className="w-4 h-4 text-[#3B82F6]" />
          </div>
          <p className="text-2xl font-black text-white font-mono mt-2">
            {safeMiner.dependencies.length}
          </p>
          <span className="text-[10px] font-mono text-[#666] block mt-0.5">Análise de CVEs</span>
        </button>

        <button
          onClick={() => setActiveSubTab('SINKS')}
          className={`p-4 border text-left transition-all col-span-2 sm:col-span-1 ${
            activeSubTab === 'SINKS'
              ? 'bg-[#111] border-[#FF3E00] shadow-[0_0_15px_rgba(255,62,0,0.15)]'
              : 'bg-[#0A0A0A] border-[#1F1F1F] hover:border-[#333]'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-[#888]">DOM Sinks</span>
            <Flame className="w-4 h-4 text-[#EF4444]" />
          </div>
          <p className="text-2xl font-black text-white font-mono mt-2">
            {safeMiner.dangerousSinks.length}
          </p>
          <span className="text-[10px] font-mono text-[#666] block mt-0.5">eval, innerHTML, XSS</span>
        </button>
      </div>

      {/* Search Input Bar */}
      <div className="bg-[#0A0A0A] p-4 border border-[#222] flex items-center justify-between gap-4">
        <div className="relative w-full max-w-md">
          <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Filtrar por nome, bucket, claim, arquivo ou CVE..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          />
        </div>
        <div className="text-[11px] font-mono text-[#888]">
          Mostrando aba ativa: <span className="text-[#FF3E00] font-bold">{activeSubTab}</span>
        </div>
      </div>

      {/* SUBTAB 1: CLOUD BUCKETS */}
      {activeSubTab === 'BUCKETS' && (
        <div className="space-y-4">
          {filteredBuckets.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-[#1F1F1F] p-12 text-center">
              <Cloud className="w-8 h-8 text-[#444] mx-auto mb-3" />
              <p className="text-sm font-mono text-[#888]">Nenhum Cloud Storage Bucket detectado nos arquivos analisados.</p>
            </div>
          ) : (
            filteredBuckets.map((bucket) => (
              <div key={bucket.id} className="bg-[#0A0A0A] border border-[#1F1F1F] hover:border-[#333] transition-colors p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="px-2.5 py-1 text-[10px] font-mono font-black uppercase tracking-wider bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30">
                      {bucket.provider}
                    </span>
                    <span className="text-base font-bold font-mono text-white">
                      {bucket.bucketName}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs font-mono text-[#666]">
                    <span>{bucket.file}:{bucket.line}</span>
                  </div>
                </div>

                <p className="text-xs text-[#AAA] font-mono leading-relaxed">
                  {bucket.riskDescription}
                </p>

                <div className="bg-[#050505] border border-[#1A1A1A] p-3 text-xs font-mono text-[#00FF41] flex items-center justify-between gap-3 overflow-x-auto">
                  <span className="truncate">{bucket.url}</span>
                  <button
                    onClick={() => handleCopy(bucket.url, `${bucket.id}-url`)}
                    className="shrink-0 p-1.5 bg-[#111] hover:bg-[#222] border border-[#333] text-white"
                    title="Copiar URL"
                  >
                    {copiedId === `${bucket.id}-url` ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                {bucket.checkCommand && (
                  <div className="bg-[#0D0D0D] border border-[#222] p-3 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono text-[#888] flex items-center gap-1.5 uppercase font-bold">
                        <Terminal className="w-3 h-3 text-[#FF3E00]" />
                        Comando de auditoria de permissões públicas:
                      </span>
                      <button
                        onClick={() => handleCopy(bucket.checkCommand!, `${bucket.id}-cmd`)}
                        className="text-[10px] font-mono text-[#FF3E00] hover:underline flex items-center gap-1"
                      >
                        {copiedId === `${bucket.id}-cmd` ? 'Copiado!' : 'Copiar Comando'}
                      </button>
                    </div>
                    <pre className="text-xs font-mono text-[#E0E0E0] overflow-x-auto">
                      {bucket.checkCommand}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* SUBTAB 2: JWT TOKENS */}
      {activeSubTab === 'JWTS' && (
        <div className="space-y-4">
          {filteredJwts.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-[#1F1F1F] p-12 text-center">
              <KeyRound className="w-8 h-8 text-[#444] mx-auto mb-3" />
              <p className="text-sm font-mono text-[#888]">Nenhum token JWT codificado foi detectado nos arquivos analisados.</p>
            </div>
          ) : (
            filteredJwts.map((jwt) => (
              <div key={jwt.id} className="bg-[#0A0A0A] border border-[#1F1F1F] hover:border-[#333] transition-colors p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="px-2.5 py-1 text-[10px] font-mono font-black uppercase tracking-wider bg-[#FF7A00]/10 text-[#FF7A00] border border-[#FF7A00]/30">
                      ALG: {jwt.algorithm}
                    </span>
                    {jwt.isExpired ? (
                      <span className="px-2 py-0.5 text-[10px] font-mono bg-[#331111] text-[#FF5555] border border-[#552222]">
                        EXPIRADO ({jwt.expiresAt})
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 text-[10px] font-mono bg-[#081F0E] text-[#00FF41] border border-[#00FF41]/30">
                        VÁLIDO / ATIVO
                      </span>
                    )}
                  </div>

                  <span className="text-xs font-mono text-[#666]">{jwt.file}:{jwt.line}</span>
                </div>

                {jwt.risks.length > 0 && (
                  <div className="bg-[#220700] border border-[#FF3E00]/40 p-3 space-y-1">
                    {jwt.risks.map((risk, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-xs font-mono text-[#FF7A00]">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 text-[#FF3E00] mt-0.5" />
                        <span>{risk}</span>
                      </div>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Header Payload JSON */}
                  <div className="bg-[#050505] border border-[#1F1F1F] p-3 space-y-1.5">
                    <span className="text-[10px] font-mono text-[#888] uppercase font-bold">Header Decodificado:</span>
                    <pre className="text-xs font-mono text-[#00FF41] overflow-x-auto max-h-36">
                      {JSON.stringify(jwt.header, null, 2)}
                    </pre>
                  </div>

                  {/* Payload Claims JSON */}
                  <div className="bg-[#050505] border border-[#1F1F1F] p-3 space-y-1.5">
                    <span className="text-[10px] font-mono text-[#888] uppercase font-bold">Payload Claims:</span>
                    <pre className="text-xs font-mono text-[#3B82F6] overflow-x-auto max-h-36">
                      {JSON.stringify(jwt.payload, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="bg-[#0D0D0D] border border-[#1A1A1A] p-2.5 flex items-center justify-between text-xs font-mono text-[#888]">
                  <span className="truncate">Preview: {jwt.token}</span>
                  <button
                    onClick={() => handleCopy(jwt.token, `${jwt.id}-token`)}
                    className="p-1 bg-[#1A1A1A] text-white hover:bg-[#222]"
                    title="Copiar token"
                  >
                    {copiedId === `${jwt.id}-token` ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* SUBTAB 3: SOURCE MAPS */}
      {activeSubTab === 'SOURCEMAPS' && (
        <div className="space-y-4">
          {filteredSourceMaps.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-[#1F1F1F] p-12 text-center">
              <FileCode className="w-8 h-8 text-[#444] mx-auto mb-3" />
              <p className="text-sm font-mono text-[#888]">Nenhum Source Map exposto foi encontrado nos arquivos analisados.</p>
            </div>
          ) : (
            filteredSourceMaps.map((sm) => (
              <div key={sm.id} className="bg-[#0A0A0A] border border-[#1F1F1F] hover:border-[#333] transition-colors p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30">
                      {sm.type}
                    </span>
                    <span className="text-sm font-bold font-mono text-white truncate max-w-md">
                      {sm.url}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-[#666]">{sm.file}:{sm.line}</span>
                </div>

                <p className="text-xs font-mono text-[#AAA] leading-relaxed">
                  {sm.riskDescription}
                </p>

                <div className="bg-[#050505] border border-[#1F1F1F] p-2 text-xs font-mono text-[#FF3E00]">
                  Snippet: {sm.snippet}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* SUBTAB 4: BUNDLED LIBRARIES */}
      {activeSubTab === 'DEPS' && (
        <div className="space-y-4">
          {filteredDependencies.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-[#1F1F1F] p-12 text-center">
              <Layers className="w-8 h-8 text-[#444] mx-auto mb-3" />
              <p className="text-sm font-mono text-[#888]">Nenhuma assinatura de biblioteca legada identificada nos bundles.</p>
            </div>
          ) : (
            filteredDependencies.map((dep) => (
              <div key={dep.id} className="bg-[#0A0A0A] border border-[#1F1F1F] hover:border-[#333] transition-colors p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold ${
                      dep.status === 'VULNERABLE'
                        ? 'bg-[#FF3E00]/10 text-[#FF3E00] border border-[#FF3E00]/30'
                        : dep.status === 'OUTDATED'
                        ? 'bg-[#FF7A00]/10 text-[#FF7A00] border border-[#FF7A00]/30'
                        : 'bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30'
                    }`}>
                      {dep.status}
                    </span>
                    <span className="text-base font-bold font-mono text-white">
                      {dep.name} v{dep.version}
                    </span>
                    {dep.cveAdvisory && (
                      <span className="text-xs font-mono text-[#FF3E00] font-bold">
                        [{dep.cveAdvisory}]
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-mono text-[#666]">{dep.file}:{dep.line}</span>
                </div>

                <p className="text-xs font-mono text-[#AAA] leading-relaxed">
                  {dep.description}
                </p>
              </div>
            ))
          )}
        </div>
      )}

      {/* SUBTAB 5: DANGEROUS DOM SINKS */}
      {activeSubTab === 'SINKS' && (
        <div className="space-y-4">
          {onNavigateToDataFlow && (
            <div className="bg-[#140604] border border-[#FF3E00]/40 p-4 rounded flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-[0_0_15px_rgba(255,62,0,0.1)]">
              <div className="flex items-center gap-3">
                <Network className="w-5 h-5 text-[#FF3E00] shrink-0 animate-pulse" />
                <div>
                  <h4 className="text-xs font-bold text-white uppercase font-mono">Visualizador de Grafo D3 de Fluxo de Dados</h4>
                  <p className="text-[11px] text-[#888] font-mono mt-0.5">
                    Rastreie como os endpoints de API detectados fluem até estes perigosos sinks através das funções consumidoras do código.
                  </p>
                </div>
              </div>
              <button
                onClick={onNavigateToDataFlow}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#FF3E00] hover:bg-white hover:text-black text-white font-mono text-xs font-bold uppercase transition-colors shrink-0"
              >
                <span>Explorar no Grafo D3</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {filteredSinks.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-[#1F1F1F] p-12 text-center">
              <ShieldCheck className="w-8 h-8 text-[#00FF41] mx-auto mb-3" />
              <p className="text-sm font-mono text-[#888]">Nenhum sink DOM perigoso detectado.</p>
            </div>
          ) : (
            filteredSinks.map((sink) => (
              <div key={sink.id} className="bg-[#0A0A0A] border border-[#1F1F1F] hover:border-[#333] transition-colors p-5 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 text-[10px] font-mono font-bold ${
                      sink.severity === 'CRITICAL'
                        ? 'bg-[#FF3E00] text-white'
                        : sink.severity === 'HIGH'
                        ? 'bg-[#FF7A00] text-black'
                        : 'bg-[#FFB703] text-black'
                    }`}>
                      {sink.severity} // {sink.sinkType}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-[#666]">{sink.file}:{sink.line}</span>
                </div>

                <div className="bg-[#050505] border border-[#1A1A1A] p-3 text-xs font-mono text-[#FF7A00] overflow-x-auto">
                  {sink.snippet}
                </div>

                <p className="text-xs font-mono text-[#AAA]">
                  {sink.description}
                </p>

                <div className="bg-[#111] p-2.5 text-xs font-mono text-[#00FF41]">
                  <span className="font-bold text-white uppercase text-[10px] block mb-0.5">Remediação Recomendada:</span>
                  {sink.remediation}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};
