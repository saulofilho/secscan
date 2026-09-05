import React, { useState } from 'react';
import { Route, Search, Filter, ShieldAlert, ArrowUpRight, Copy, Check, Download, FileText, Terminal, Code, Radio } from 'lucide-react';
import { ApiEndpointFinding } from '../types';
import { exportToBurpScope, exportToCleanUrlList } from '../lib/linkFinderEngine';

interface ApiPathsViewProps {
  endpoints: ApiEndpointFinding[];
}

export const ApiPathsView: React.FC<ApiPathsViewProps> = ({ endpoints = [] }) => {
  const safeEndpoints = Array.isArray(endpoints) ? endpoints : [];
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'ALL' | 'INTERNAL' | 'PUBLIC'>('ALL');
  const [scopeFilter, setScopeFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [methodFilter, setMethodFilter] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredEndpoints = safeEndpoints.filter(ep => {
    if (filterType === 'INTERNAL' && !ep.isInternalOrAdmin) return false;
    if (filterType === 'PUBLIC' && ep.isInternalOrAdmin) return false;
    if (scopeFilter !== 'ALL' && ep.scope !== scopeFilter) return false;
    if (typeFilter !== 'ALL' && ep.urlType !== typeFilter) return false;
    if (methodFilter !== 'ALL' && ep.method !== methodFilter) return false;
    if (searchTerm && !ep.path.toLowerCase().includes(searchTerm.toLowerCase()) && !ep.file.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    return true;
  });

  const handleCopy = (path: string, id: string) => {
    navigator.clipboard.writeText(path);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleExportJson = () => {
    const json = JSON.stringify(filteredEndpoints, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'linkfinder-endpoints.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportBurp = () => {
    const xml = exportToBurpScope(filteredEndpoints);
    const blob = new Blob([xml], { type: 'application/xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'burp-suite-scope.xml';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCleanUrls = () => {
    const list = exportToCleanUrlList(filteredEndpoints);
    const blob = new Blob([list], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'endpoints-clean-list.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const internalCount = safeEndpoints.filter(e => e.isInternalOrAdmin).length;

  return (
    <div className="space-y-6 pb-12">
      {/* Header Overview Card */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // PORTSWIGGER JS-LINK-FINDER ENGINE
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333]">
              {endpoints.length} ENDPOINTS DISCOVERED
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1">
            API Endpoints & LinkFinder
          </h1>
          <p className="text-xs font-mono text-[#888] mt-1.5 max-w-2xl leading-relaxed">
            Mecanismo baseado no PortSwigger js-link-finder & Gerben Javado: extrai rotas REST, parâmetros (<code className="text-[#FF7A00]">?query</code>, <code className="text-[#FF7A00]">:id</code>), endpoints GraphQL, WebSockets e gera escopo XML para o Burp Suite e probes cURL.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={handleExportBurp}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-white bg-[#111] hover:bg-[#FF3E00] border border-[#333] hover:border-[#FF3E00] transition-colors"
            title="Exportar escopo compatível com Burp Suite"
          >
            <ShieldAlert className="w-3 h-3 text-[#FF7A00]" />
            <span>Burp Scope XML</span>
          </button>
          <button
            onClick={handleExportCleanUrls}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-white bg-[#111] hover:bg-[#222] border border-[#333] transition-colors"
            title="Exportar lista limpa de URLs em TXT"
          >
            <FileText className="w-3 h-3 text-[#00FF41]" />
            <span>URLs TXT</span>
          </button>
          <button
            onClick={handleExportJson}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors"
          >
            <Download className="w-3 h-3 text-[#FF3E00]" />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0A0A0A] p-4 border border-[#222] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-[240px]">
          <div className="relative w-full max-w-md">
            <Search className="w-3.5 h-3.5 text-[#666] absolute left-3 top-3" />
            <input
              type="text"
              placeholder="Buscar por rota, parâmetro ou arquivo..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Scope Filter */}
          <select
            value={scopeFilter}
            onChange={(e) => setScopeFilter(e.target.value)}
            className="text-xs py-2 px-3 bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          >
            <option value="ALL">Todo Escopo</option>
            <option value="IN_SCOPE">In Scope (Interno/App)</option>
            <option value="INTERNAL">Rotas Admin / Privilegiadas</option>
            <option value="EXTERNAL">Serviços Externos</option>
            <option value="CDN">CDNs & Assets</option>
          </select>

          {/* URL Type Filter */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="text-xs py-2 px-3 bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          >
            <option value="ALL">Todos os Tipos</option>
            <option value="RELATIVE_PATH">Rotas Relativas (/api/...)</option>
            <option value="FULL_URL">URLs Completas (http://)</option>
            <option value="GRAPHQL">GraphQL</option>
            <option value="WEBSOCKET">WebSockets (ws://)</option>
          </select>

          {/* HTTP Method */}
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="text-xs py-2 px-3 bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          >
            <option value="ALL">Todos Métodos</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#080808] border-b border-[#222] text-[#666] uppercase tracking-[0.2em] font-black text-[10px]">
              <tr>
                <th className="px-4 py-3.5">Method</th>
                <th className="px-4 py-3.5">Endpoint & Parameters</th>
                <th className="px-4 py-3.5">Type & Scope</th>
                <th className="px-4 py-3.5">Source File</th>
                <th className="px-4 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#141414] font-mono">
              {filteredEndpoints.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-12 text-center text-[#666] font-mono text-xs">
                    NO_ENDPOINTS_MATCHING_FILTER
                  </td>
                </tr>
              ) : (
                filteredEndpoints.map((ep) => {
                  const methodColors: Record<string, string> = {
                    GET: 'bg-[#001433] text-[#3366FF] border-[#3366FF]/40',
                    POST: 'bg-[#081f0e] text-[#00FF41] border-[#00FF41]/40',
                    PUT: 'bg-[#261c02] text-amber-400 border-amber-500/40',
                    DELETE: 'bg-[#220700] text-[#FF3E00] border-[#FF3E00]/40',
                    PATCH: 'bg-[#180026] text-purple-400 border-purple-500/40'
                  };

                  return (
                    <tr key={ep.id} className="hover:bg-[#111] transition-colors">
                      {/* Method */}
                      <td className="px-4 py-3.5 shrink-0 align-top">
                        <span className={`px-2 py-0.5 text-[9px] font-mono font-black border uppercase tracking-wider ${
                          methodColors[ep.method || 'GET'] || 'bg-[#141414] text-[#AAA] border-[#333]'
                        }`}>
                          {ep.method || 'GET'}
                        </span>
                      </td>

                      {/* Path & Parameters */}
                      <td className="px-4 py-3.5 text-white font-mono align-top">
                        <div className="font-bold break-all flex items-center gap-2">
                          <span>{ep.path}</span>
                        </div>
                        {ep.params && ep.params.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {ep.params.map((param, pIdx) => (
                              <span key={pIdx} className="px-1.5 py-0.5 text-[9px] font-mono bg-[#181818] text-[#FF7A00] border border-[#282828]">
                                {param}
                              </span>
                            ))}
                          </div>
                        )}
                        {ep.snippet && (
                          <div className="text-[10px] text-[#555] font-mono truncate max-w-md mt-1">
                            {ep.snippet}
                          </div>
                        )}
                      </td>

                      {/* Type & Scope */}
                      <td className="px-4 py-3.5 align-top">
                        <div className="flex flex-col gap-1">
                          {ep.isInternalOrAdmin ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono font-bold bg-[#220700] text-[#FF3E00] border border-[#FF3E00]/40 uppercase tracking-wide w-fit">
                              <ShieldAlert className="w-2.5 h-2.5 text-[#FF3E00]" />
                              <span>ADMIN / INTERNAL</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono bg-[#141414] text-[#888] border border-[#222] uppercase w-fit">
                              <span>{ep.scope || 'IN_SCOPE'}</span>
                            </span>
                          )}
                          {ep.urlType && (
                            <span className="text-[9px] font-mono text-[#666]">
                              [{ep.urlType}]
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Source File */}
                      <td className="px-4 py-3.5 text-[#666] truncate max-w-xs font-mono text-[11px] align-top">
                        {ep.file}:{ep.line}
                      </td>

                      {/* Copy Action & Curl */}
                      <td className="px-4 py-3.5 text-right align-top">
                        <div className="flex items-center justify-end gap-1.5">
                          {ep.curlCommand && (
                            <button
                              onClick={() => handleCopy(ep.curlCommand!, `${ep.id}-curl`)}
                              className="p-1.5 text-[#888] hover:text-[#00FF41] border border-[#222] hover:border-[#00FF41]/40 bg-[#111] transition-colors"
                              title="Copiar comando cURL"
                            >
                              {copiedId === `${ep.id}-curl` ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Terminal className="w-3.5 h-3.5" />}
                            </button>
                          )}
                          <button
                            onClick={() => handleCopy(ep.path, ep.id)}
                            className="p-1.5 text-[#666] hover:text-white border border-[#222] hover:border-[#333] bg-[#111] transition-colors"
                            title="Copiar endpoint"
                          >
                            {copiedId === ep.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

