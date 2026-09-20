import React, { useState, useMemo } from 'react';
import { 
  FileSpreadsheet, 
  Download, 
  Copy, 
  Check, 
  Layers, 
  ShieldCheck, 
  FileCode, 
  Package, 
  Hash, 
  Sparkles,
  ExternalLink
} from 'lucide-react';
import { ScannedFile } from '../types';
import { generateCycloneDxSbom, generateSpdxSbom, SbomDocument } from '../lib/sbomGenerator';

interface SbomGeneratorViewProps {
  files: ScannedFile[];
}

export const SbomGeneratorView: React.FC<SbomGeneratorViewProps> = ({ files }) => {
  const [format, setFormat] = useState<'CycloneDX' | 'SPDX'>('CycloneDX');
  const [copiedJson, setCopiedJson] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const sbom: SbomDocument = useMemo(() => {
    return format === 'CycloneDX' ? generateCycloneDxSbom(files) : generateSpdxSbom(files);
  }, [files, format]);

  const handleDownload = () => {
    const filename = `${sbom.appName}-${sbom.format.toLowerCase()}-sbom-${Date.now()}.json`;
    const blob = new Blob([sbom.rawJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(sbom.rawJson);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const cosignCmd = `cosign attest --yes --key cosign.key --predicate ${sbom.appName}-sbom.json my-registry.io/${sbom.appName}:${sbom.appVersion}`;

  const handleCopyCmd = () => {
    navigator.clipboard.writeText(cosignCmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
              <FileSpreadsheet className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase">
              SBOM Generator &amp; Supply Chain Attestation
            </h1>
            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800/60 font-bold">
              OWASP CycloneDX &amp; SPDX 2.3
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Geração de Software Bill of Materials (SBOM) compatível com a Ordem Executiva dos EUA 14028 e assinatura Cosign/in-toto.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownload}
            className="h-8 px-3 rounded inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-white bg-indigo-600 hover:bg-indigo-500 transition-colors cursor-pointer shadow"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Baixar SBOM ({format})</span>
          </button>
        </div>
      </div>

      {/* Format Toggle & Metadata Header */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-2 md:col-span-1">
          <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">Padrão de Especificação</span>
          <div className="flex rounded-lg bg-black/60 p-1 border border-[#222]">
            <button
              onClick={() => setFormat('CycloneDX')}
              className={`flex-1 py-1.5 rounded text-xs font-bold transition-all cursor-pointer ${
                format === 'CycloneDX' ? 'bg-indigo-600 text-white shadow' : 'text-zinc-400 hover:text-white'
              }`}
            >
              CycloneDX v1.5
            </button>
            <button
              onClick={() => setFormat('SPDX')}
              className={`flex-1 py-1.5 rounded text-xs font-bold transition-all cursor-pointer ${
                format === 'SPDX' ? 'bg-indigo-600 text-white shadow' : 'text-zinc-400 hover:text-white'
              }`}
            >
              SPDX v2.3
            </button>
          </div>
        </div>

        <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl md:col-span-3 grid grid-cols-2 sm:grid-cols-3 gap-3">
          <div>
            <span className="text-[10px] text-zinc-500 uppercase block">Ativo Principal</span>
            <span className="text-sm font-bold text-white">{sbom.appName}</span>
            <span className="text-[11px] text-zinc-400 block">v{sbom.appVersion}</span>
          </div>
          <div>
            <span className="text-[10px] text-zinc-500 uppercase block">Componentes Catalogados</span>
            <span className="text-sm font-bold text-indigo-400">{sbom.totalComponents} bibliotecas</span>
            <span className="text-[11px] text-zinc-500 block">com hashes SHA-256</span>
          </div>
          <div>
            <span className="text-[10px] text-zinc-500 uppercase block">Identificador Único</span>
            <span className="text-[11px] text-zinc-300 truncate block font-mono">{sbom.serialNumber}</span>
            <span className="text-[10px] text-emerald-400 block">Timestamp ISO 8601 OK</span>
          </div>
        </div>
      </div>

      {/* Cosign Attestation Preview */}
      <div className="bg-[#0C0C0C] border border-indigo-900/30 p-4 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-950/60 text-indigo-400 border border-indigo-800/60">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-zinc-200">Assinatura Criptográfica via Cosign / Sigstore</h3>
            <p className="text-[11px] text-zinc-400">Garante autenticidade e não-repúdio do manifesto na esteira CI/CD.</p>
          </div>
        </div>
        <button
          onClick={handleCopyCmd}
          className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer self-start sm:self-auto shrink-0"
        >
          {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copiedCmd ? 'Comando Copiado!' : 'Copiar Comando Cosign'}</span>
        </button>
      </div>

      {/* Component Inventory Table */}
      <div className="bg-[#0C0C0C] border border-[#222] rounded-xl overflow-hidden">
        <div className="p-4 border-b border-[#222] flex items-center justify-between">
          <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider">
            Inventário de Componentes do SBOM ({sbom.components.length})
          </span>
          <span className="text-[10px] text-zinc-500">Formato: Package URL (purl)</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#121212] text-zinc-400 text-[10px] uppercase border-b border-[#222]">
              <tr>
                <th className="px-4 py-2.5">Componente</th>
                <th className="px-4 py-2.5">Versão</th>
                <th className="px-4 py-2.5">Package URL (purl)</th>
                <th className="px-4 py-2.5">Licença</th>
                <th className="px-4 py-2.5">Hash SHA-256</th>
                <th className="px-4 py-2.5 text-right">Vulnerabilidades</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {sbom.components.map((comp, idx) => (
                <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                  <td className="px-4 py-2.5 font-bold text-white flex items-center gap-1.5">
                    <Package className="w-3.5 h-3.5 text-indigo-400" />
                    <span>{comp.name}</span>
                  </td>
                  <td className="px-4 py-2.5 text-zinc-300">v{comp.version}</td>
                  <td className="px-4 py-2.5 text-zinc-400 font-mono text-[11px]">{comp.purl}</td>
                  <td className="px-4 py-2.5">
                    <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 text-[10px]">
                      {comp.license}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-zinc-500 font-mono text-[10px] max-w-[140px] truncate">
                    {comp.hashes.sha256}
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    {comp.vulnerabilitiesCount > 0 ? (
                      <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 text-[10px] font-bold">
                        {comp.vulnerabilitiesCount} CVEs
                      </span>
                    ) : (
                      <span className="text-emerald-400 text-[10px]">0 CVE</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw JSON Code Inspector */}
      <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-4 space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold text-zinc-400 uppercase tracking-wider">
            Visualizador do Manifesto SBOM ({format} JSON)
          </span>
          <button
            onClick={handleCopyJson}
            className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedJson ? 'JSON Copiado!' : 'Copiar JSON'}</span>
          </button>
        </div>
        <pre className="p-4 bg-black rounded-lg text-indigo-300 text-[11px] leading-relaxed max-h-72 overflow-y-auto border border-white/5 font-mono">
          <code>{sbom.rawJson}</code>
        </pre>
      </div>
    </div>
  );
};
