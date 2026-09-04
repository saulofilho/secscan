import React, { useState } from 'react';
import { Route, Search, Filter, ShieldAlert, ArrowUpRight, Copy, Check, Download } from 'lucide-react';
import { ApiEndpointFinding } from '../types';

interface ApiPathsViewProps {
  endpoints: ApiEndpointFinding[];
}

export const ApiPathsView: React.FC<ApiPathsViewProps> = ({ endpoints = [] }) => {
  const safeEndpoints = Array.isArray(endpoints) ? endpoints : [];
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<'ALL' | 'INTERNAL' | 'PUBLIC'>('ALL');
  const [methodFilter, setMethodFilter] = useState<string>('ALL');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredEndpoints = safeEndpoints.filter(ep => {
    if (filterType === 'INTERNAL' && !ep.isInternalOrAdmin) return false;
    if (filterType === 'PUBLIC' && ep.isInternalOrAdmin) return false;
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
    a.download = 'api-endpoints-inventory.json';
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
              // ATTACK SURFACE MAPPING
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333]">
              {endpoints.length} ROUTES DISCOVERED
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1">
            API Endpoints Inventory
          </h1>
          <p className="text-xs font-mono text-[#888] mt-1.5 max-w-2xl leading-relaxed">
            Mapeamento automático de superfícies de ataque: identifica rotas internas, endpoints com `/admin`, chamadas REST via `axios`/`fetch` e routers Express.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleExportJson}
            className="inline-flex items-center gap-2 px-4 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Exportar JSON</span>
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
              placeholder="Buscar por rota, método ou arquivo..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
            />
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Internal vs Public */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value as any)}
            className="text-xs py-2 px-3 bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          >
            <option value="ALL">Todas as Rotas ({endpoints.length})</option>
            <option value="INTERNAL">Rotas Administrativas / Internas ({internalCount})</option>
            <option value="PUBLIC">Rotas Públicas ({endpoints.length - internalCount})</option>
          </select>

          {/* HTTP Method */}
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="text-xs py-2 px-3 bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
          >
            <option value="ALL">Todos os Métodos</option>
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
                <th className="px-4 py-3.5">Endpoint Path</th>
                <th className="px-4 py-3.5">Risk Vector</th>
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
                      <td className="px-4 py-3.5 shrink-0">
                        <span className={`px-2 py-0.5 text-[9px] font-mono font-black border uppercase tracking-wider ${
                          methodColors[ep.method || 'GET'] || 'bg-[#141414] text-[#AAA] border-[#333]'
                        }`}>
                          {ep.method || 'GET'}
                        </span>
                      </td>

                      {/* Path */}
                      <td className="px-4 py-3.5 text-white font-bold font-mono">
                        <span className="break-all">{ep.path}</span>
                      </td>

                      {/* Risk Classification */}
                      <td className="px-4 py-3.5">
                        {ep.isInternalOrAdmin ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono font-bold bg-[#220700] text-[#FF3E00] border border-[#FF3E00]/40 uppercase tracking-wide">
                            <ShieldAlert className="w-3 h-3 text-[#FF3E00]" />
                            <span>INTERNAL / ADMIN</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono bg-[#141414] text-[#888] border border-[#222] uppercase">
                            <span>STANDARD</span>
                          </span>
                        )}
                      </td>

                      {/* Source File */}
                      <td className="px-4 py-3.5 text-[#666] truncate max-w-xs font-mono text-[11px]">
                        {ep.file}:{ep.line}
                      </td>

                      {/* Copy Action */}
                      <td className="px-4 py-3.5 text-right">
                        <button
                          onClick={() => handleCopy(ep.path, ep.id)}
                          className="p-1.5 text-[#666] hover:text-white border border-[#222] hover:border-[#333] bg-[#111] transition-colors"
                          title="Copiar endpoint"
                        >
                          {copiedId === ep.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
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
