import React, { useState } from 'react';
import { 
  FileCode, 
  FolderTree, 
  Upload, 
  Eye, 
  EyeOff, 
  Copy, 
  Check, 
  AlertTriangle, 
  ShieldAlert, 
  Code2, 
  Plus, 
  Ban,
  Sparkles,
  Search,
  Filter,
  BookOpen,
  Terminal,
  Wrench
} from 'lucide-react';
import { ScannedFile, ScanFinding, SeverityLevel, IgnorePatternItem } from '../types';
import { SecurityGlossaryTooltip, SecurityGlossaryInlineCard } from './SecurityGlossary';
import { SecurityGlossaryEntry } from '../lib/securityGlossary';
import { SecurityRemediationWikiModal } from './SecurityRemediationWikiModal';

interface ScannerViewProps {
  files: ScannedFile[];
  findings: ScanFinding[];
  selectedFile: ScannedFile | null;
  onSelectFile: (file: ScannedFile) => void;
  onFileUpload: (files: FileList) => void;
  onAddCustomFile: (name: string, content: string) => void;
  ignorePatterns?: IgnorePatternItem[];
  onOpenIgnoreModal?: () => void;
  onQuickIgnore?: (pattern: string, description?: string) => void;
  onOpenGlossary?: (entry?: SecurityGlossaryEntry) => void;
  onOpenRemediationWiki?: (finding?: ScanFinding) => void;
}

export const ScannerView: React.FC<ScannerViewProps> = ({
  files = [],
  findings = [],
  selectedFile,
  onSelectFile,
  onFileUpload,
  onAddCustomFile,
  ignorePatterns = [],
  onOpenIgnoreModal,
  onQuickIgnore,
  onOpenGlossary,
  onOpenRemediationWiki
}) => {
  const safeFiles = Array.isArray(files) ? files : [];
  const safeFindings = Array.isArray(findings) ? findings : [];
  const safeIgnorePatterns = Array.isArray(ignorePatterns) ? ignorePatterns : [];

  const [showRawSecret, setShowRawSecret] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [showPasteModal, setShowPasteModal] = useState(false);
  const [pasteFileName, setPasteFileName] = useState('customService.js');
  const [pasteContent, setPasteContent] = useState('');

  // Security Remediation Wiki Modal State
  const [isRemediationWikiOpen, setIsRemediationWikiOpen] = useState(false);
  const [selectedWikiFinding, setSelectedWikiFinding] = useState<ScanFinding | null>(null);

  const handleOpenRemediationWiki = (finding?: ScanFinding) => {
    setSelectedWikiFinding(finding || null);
    setIsRemediationWikiOpen(true);
    if (onOpenRemediationWiki) {
      onOpenRemediationWiki(finding);
    }
  };

  const activeFile = selectedFile || safeFiles[0];
  const fileFindings = safeFindings.filter(f => f.file === activeFile?.path);

  const filteredFindings = fileFindings.filter(f => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchTerm && !f.ruleName.toLowerCase().includes(searchTerm.toLowerCase()) && !f.snippet.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    return true;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(id);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleCreateCustomFile = () => {
    if (!pasteContent.trim()) return;
    onAddCustomFile(pasteFileName.trim() || 'snippet.js', pasteContent);
    setShowPasteModal(false);
    setPasteContent('');
  };

  // Generate safe remediated snippet (replaces hardcoded secret with process.env)
  const getSafeSnippet = (finding: ScanFinding) => {
    const envVarName = finding.ruleId.toUpperCase().replace(/[^A-Z0-9]/g, '_');
    return finding.snippet.replace(finding.matchedSecret, `process.env.${envVarName}`);
  };

  const lines = activeFile?.content ? activeFile.content.split('\n') : [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pb-12">
      {/* Left Sidebar: File Tree & Upload */}
      <div className="lg:col-span-4 space-y-4">
        {/* Actions header */}
        <div className="bg-[#0A0A0A] p-5 border border-[#222] space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#666] flex items-center gap-2">
              <FolderTree className="w-3.5 h-3.5 text-[#FF3E00]" />
              <span>Workspace Files ({files.length})</span>
            </h2>
            <button
              onClick={() => setShowPasteModal(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.15em] text-white border border-[#333] bg-[#111] hover:bg-white hover:text-black transition-colors"
            >
              <Plus className="w-3 h-3" />
              <span>Paste Code</span>
            </button>
          </div>

          {/* File Upload Drag & Drop Area */}
          <label className="border border-dashed border-[#333] hover:border-[#FF3E00] hover:bg-[#FF3E00]/5 p-5 flex flex-col items-center justify-center cursor-pointer transition-colors text-center group">
            <Upload className="w-5 h-5 text-[#666] group-hover:text-[#FF3E00] mb-2 transition-colors" />
            <span className="text-xs font-black uppercase tracking-wider text-white">Carregar Arquivo ou Pasta</span>
            <span className="text-[10px] font-mono text-[#666] mt-1">ARRASTE JS, TS, ENV, JSON</span>
            <input
              type="file"
              multiple
              className="hidden"
              onChange={(e) => e.target.files && onFileUpload(e.target.files)}
            />
          </label>

          {/* Global Ignore List Shortcut Card */}
          {onOpenIgnoreModal && (
            <button
              id="btn-scanner-global-ignore"
              onClick={onOpenIgnoreModal}
              className="w-full flex items-center justify-between p-3.5 bg-[#0D0500] border border-[#FF3E00]/40 hover:border-[#FF3E00] hover:bg-[#1A0900] text-white transition-all group text-left cursor-pointer"
              title="Gerenciar lista de exclusão global (Global Ignore List)"
            >
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 bg-[#220700] border border-[#FF3E00]/50 flex items-center justify-center text-[#FF3E00] group-hover:scale-105 transition-transform shrink-0">
                  <Ban className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[11px] font-black uppercase tracking-wider font-mono text-white flex items-center gap-1.5">
                    <span>Global Ignore List</span>
                    <span className="text-[8.5px] px-1 py-0.2 bg-[#FF3E00]/20 text-[#FF3E00] border border-[#FF3E00]/40">CONFIG</span>
                  </div>
                  <div className="text-[9.5px] font-mono text-[#888]">Exclusão de arquivos/diretórios</div>
                </div>
              </div>

              <div className="text-right font-mono shrink-0">
                <div className="text-[10px] text-[#00FF41] font-bold">
                  {safeIgnorePatterns.filter(p => p && p.enabled).length} ATIVOS
                </div>
                <div className="text-[9px] text-[#888]">
                  {safeFiles.filter(f => f.isIgnored).length} ignorados
                </div>
              </div>
            </button>
          )}
        </div>

        {/* File List */}
        <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden">
          <div className="px-4 py-3 bg-[#080808] border-b border-[#222] text-[10px] font-black tracking-[0.2em] uppercase text-[#666] flex items-center justify-between">
            <span>Explorador de Arquivos</span>
            <span className="font-mono text-[10px] text-[#444]">COUNT: {safeFiles.length}</span>
          </div>

          <div className="max-h-[500px] overflow-y-auto">
            {safeFiles.map((file) => {
              const isSelected = activeFile?.path === file.path;
              const fileFindingCount = safeFindings.filter(f => f.file === file.path).length;

              return (
                <button
                  key={file.path}
                  onClick={() => onSelectFile(file)}
                  className={`w-full text-left px-4 py-3 flex items-center justify-between transition-colors border-b border-[#141414] ${
                    isSelected
                      ? 'bg-[#141414] border-l-2 border-l-[#FF3E00] text-white font-bold'
                      : 'hover:bg-[#111] text-[#888]'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0 pr-2">
                    <FileCode className={`w-3.5 h-3.5 shrink-0 ${file.isIgnored ? 'text-[#444]' : isSelected ? 'text-[#FF3E00]' : 'text-[#666]'}`} />
                    <div className="truncate">
                      <div className={`text-xs truncate font-mono ${isSelected ? 'text-white font-bold' : 'text-[#AAA]'}`}>{file.name}</div>
                      <div className="text-[10px] text-[#555] truncate font-mono">{file.path}</div>
                    </div>
                  </div>

                  <div className="shrink-0 flex items-center gap-1.5 font-mono">
                    {file.isIgnored ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono bg-[#141414] text-[#666] border border-[#222]" title={file.ignoreReason}>
                        <Ban className="w-2.5 h-2.5 text-[#555]" />
                        <span>IGNORED</span>
                      </span>
                    ) : fileFindingCount > 0 ? (
                      <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-[#220700] text-[#FF3E00] border border-[#FF3E00]/40">
                        {fileFindingCount} ALERTA{fileFindingCount > 1 ? 'S' : ''}
                      </span>
                    ) : (
                      <span className="text-[9px] font-mono text-[#00FF41] uppercase">
                        CLEAN
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Right Column: Code Viewer & Finding Highlights */}
      <div className="lg:col-span-8 space-y-4">
        {/* Active File Header */}
        <div className="bg-[#0A0A0A] p-4 border border-[#222] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-sm font-black text-white">{activeFile?.name}</span>
              {activeFile?.isIgnored && (
                <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-[#141414] text-[#888] border border-[#333]">
                  DEPENDÊNCIA IGNORADA: {activeFile.ignoreReason}
                </span>
              )}
            </div>
            <p className="text-[11px] text-[#666] font-mono mt-0.5">{activeFile?.path}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {onQuickIgnore && activeFile && !activeFile.isIgnored && (
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => onQuickIgnore(activeFile.path, `Exclusão rápida de arquivo (${activeFile.name})`)}
                  className="inline-flex items-center gap-1.5 px-3 py-2 border border-[#333] hover:border-[#FF3E00] bg-[#111] hover:bg-[#200500] text-[#AAA] hover:text-[#FF3E00] text-[10px] font-black uppercase tracking-[0.15em] transition-colors"
                  title="Excluir este arquivo de futuras análises"
                >
                  <Ban className="w-3 h-3 text-[#FF3E00]" />
                  <span>Ignorar Arquivo</span>
                </button>
                {activeFile.path.includes('/') && (
                  <button
                    onClick={() => {
                      const dir = activeFile.path.split('/').slice(0, -1).join('/');
                      onQuickIgnore(`${dir}/*`, `Exclusão do diretório ${dir}/*`);
                    }}
                    className="inline-flex items-center gap-1.5 px-2.5 py-2 border border-[#333] hover:border-[#FF3E00] bg-[#111] hover:bg-[#200500] text-[#AAA] hover:text-[#FF3E00] text-[10px] font-black uppercase tracking-[0.15em] transition-colors hidden sm:inline-flex"
                    title={`Excluir todos os arquivos da pasta ${activeFile.path.split('/').slice(0, -1).join('/')}/*`}
                  >
                    <span>Ignorar Pasta</span>
                  </button>
                )}
              </div>
            )}

            <button
              onClick={() => setShowRawSecret(!showRawSecret)}
              className="inline-flex items-center gap-2 px-3.5 py-2 border border-[#333] hover:border-white bg-[#111] hover:bg-white hover:text-black text-white text-[10px] font-black uppercase tracking-[0.15em] transition-colors"
            >
              {showRawSecret ? (
                <>
                  <EyeOff className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Ocultar Segredos</span>
                </>
              ) : (
                <>
                  <Eye className="w-3.5 h-3.5 text-[#888]" />
                  <span>Exibir Segredos Reais</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Ignored File Status Banner */}
        {activeFile?.isIgnored && (
          <div className="p-3.5 bg-[#170500] border border-[#FF3E00]/40 font-mono text-xs text-[#FFC4B0] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2.5">
            <div className="flex items-center gap-2.5">
              <Ban className="w-4 h-4 text-[#FF3E00] shrink-0" />
              <span>
                Este arquivo está <strong className="text-white">IGNORADO</strong> por política: <code className="text-[#FF3E00] bg-[#000]/60 px-1.5 py-0.5 border border-[#441205]">{activeFile.ignoreReason}</code>
              </span>
            </div>
            {onOpenIgnoreModal && (
              <button
                onClick={onOpenIgnoreModal}
                className="text-[10px] uppercase font-bold text-white bg-[#FF3E00] hover:bg-white hover:text-black px-2.5 py-1 transition-colors shrink-0 cursor-pointer"
              >
                Gerenciar Exclusões
              </button>
            )}
          </div>
        )}

        {/* Code View Canvas */}
        <div className="bg-[#050505] text-zinc-100 border border-[#222] overflow-hidden">
          <div className="px-4 py-2.5 bg-[#080808] border-b border-[#222] flex items-center justify-between text-[10px] font-mono text-[#666] uppercase tracking-wider">
            <span>Visualizador de Código-Fonte</span>
            <span>{lines.length} LINHAS</span>
          </div>

          <div className="p-4 font-mono text-xs overflow-x-auto max-h-[460px] leading-relaxed">
            {lines.map((lineContent, idx) => {
              const lineNum = idx + 1;
              const lineFindings = fileFindings.filter(f => f.line === lineNum);
              const hasAlert = lineFindings.length > 0;

              return (
                <div
                  key={idx}
                  className={`flex items-start group py-0.5 px-2 -mx-2 transition-colors ${
                    hasAlert ? 'bg-[#220700] border-l-2 border-[#FF3E00] text-rose-100' : 'hover:bg-[#111]'
                  }`}
                >
                  {/* Line Number */}
                  <span className={`w-10 text-right pr-4 shrink-0 select-none ${
                    hasAlert ? 'text-[#FF3E00] font-bold' : 'text-[#444]'
                  }`}>
                    {lineNum}
                  </span>

                  {/* Line Code */}
                  <div className="flex-1 whitespace-pre break-all">
                    {hasAlert ? (
                      <span className="flex items-center gap-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-[#FF3E00] shrink-0 inline" />
                        <span>
                          {showRawSecret 
                            ? lineContent 
                            : lineFindings.reduce((acc, f) => acc.replace(f.matchedSecret, f.maskedSecret), lineContent)
                          }
                        </span>
                      </span>
                    ) : (
                      <span>{lineContent}</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Findings List for Active File */}
        <div className="bg-[#0A0A0A] border border-[#222] p-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#1A1A1A]">
            <div>
              <h2 className="text-[11px] font-black tracking-[0.2em] text-white uppercase flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#FF3E00]" />
                <span>Detected Exposures ({fileFindings.length})</span>
              </h2>
              <p className="text-[10px] font-mono text-[#666] uppercase mt-0.5">Vulnerabilities in selected file requiring remediation</p>
            </div>

            {/* Filter controls */}
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-[#666] absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Filtrar..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8 pr-3 py-1.5 text-xs rounded-none bg-[#050505] border border-[#222] text-white font-mono focus:outline-none focus:border-[#FF3E00] w-40"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value as SeverityLevel | 'ALL')}
                className="text-xs py-1.5 px-3 rounded-none bg-[#050505] border border-[#222] text-white font-mono focus:outline-none focus:border-[#FF3E00]"
              >
                <option value="ALL">Todas Severidades</option>
                <option value="CRITICAL">Apenas Críticas</option>
                <option value="HIGH">Apenas Altas</option>
                <option value="MEDIUM">Apenas Médias</option>
                <option value="LOW">Apenas Baixas</option>
              </select>

              {/* Security Remediation Wiki Button */}
              <button
                type="button"
                id="btn-scanner-open-remediation-wiki"
                onClick={() => handleOpenRemediationWiki()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#170A00] hover:bg-[#FF3E00] border border-[#FF3E00]/40 hover:border-[#FF3E00] text-white text-xs font-mono transition-colors cursor-pointer group"
                title="Abrir a Wiki de Remediação e Patching de Segurança"
              >
                <Wrench className="w-3.5 h-3.5 text-[#FF3E00] group-hover:text-white transition-colors" />
                <span className="hidden sm:inline">Wiki de Remediação</span>
                <span className="sm:hidden">Wiki</span>
                {safeFindings.length > 0 && (
                  <span className="px-1.5 py-0.2 bg-[#FF3E00] group-hover:bg-white text-white group-hover:text-black text-[9px] font-bold">
                    {safeFindings.length}
                  </span>
                )}
              </button>

              {onOpenGlossary && (
                <button
                  type="button"
                  id="btn-scanner-open-glossary"
                  onClick={() => onOpenGlossary()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#111] hover:bg-[#200500] border border-[#333] hover:border-[#FF3E00] text-white text-xs font-mono transition-colors cursor-pointer"
                  title="Abrir o Glossário de Vulnerabilidades completo"
                >
                  <BookOpen className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span className="hidden sm:inline">Glossário</span>
                </button>
              )}
            </div>
          </div>

          <div className="mt-5 space-y-4">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center text-[#666] font-mono text-xs border border-dashed border-[#1A1A1A]">
                NO_ACTIVE_FINDINGS_IN_FILE
              </div>
            ) : (
              filteredFindings.map((finding) => (
                <div 
                  key={finding.id}
                  className="p-5 border border-[#222] bg-[#080808] space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[9px] font-mono font-black px-2 py-0.5 uppercase tracking-wider ${
                        finding.severity === 'CRITICAL' 
                          ? 'bg-[#FF3E00] text-white' 
                          : 'bg-[#FF7A00] text-black font-bold'
                      }`}>
                        {finding.severity}
                      </span>
                      <span className="text-xs font-bold text-white">{finding.ruleName}</span>
                      <span className="text-[11px] text-[#666] font-mono">L{finding.line}:{finding.column}</span>
                      
                      {/* Context-aware Security Glossary Tooltip */}
                      <SecurityGlossaryTooltip 
                        finding={finding} 
                        onOpenFullGlossary={onOpenGlossary} 
                      />

                      {/* Direct Link to Security Remediation Wiki */}
                      <button
                        type="button"
                        onClick={() => handleOpenRemediationWiki(finding)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#141414] hover:bg-[#FF3E00] text-[#AAA] hover:text-white border border-[#333] hover:border-[#FF3E00] text-[10px] font-mono transition-all group cursor-pointer"
                        title="Abrir Playbook Passo a Passo de Remediação para esta Vulnerabilidade"
                      >
                        <Wrench className="w-3 h-3 text-[#FF3E00] group-hover:text-white transition-colors" />
                        <span className="font-bold">Wiki de Remediação</span>
                      </button>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-[#FF3E00]/15 text-[#FF3E00] border border-[#FF3E00]/40 font-bold">
                        RISK SCORE: <strong className="text-white">{finding.riskScore ?? 80}</strong>/100
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-[#111] text-[#AAA] border border-[#222]">
                        ENTROPIA: <strong className="text-white">{finding.entropy}</strong>
                      </span>
                    </div>
                  </div>

                  {/* Secret Display */}
                  <div className="p-3 bg-[#000] border border-[#1A1A1A] font-mono text-xs flex items-center justify-between gap-2 overflow-x-auto">
                    <span className="text-[#FF3E00] font-bold break-all">
                      {showRawSecret ? finding.matchedSecret : finding.maskedSecret}
                    </span>
                    <button
                      onClick={() => handleCopy(finding.matchedSecret, finding.id)}
                      className="shrink-0 p-1.5 text-[#888] hover:text-white border border-[#222] bg-[#111] hover:bg-[#222] transition-colors"
                      title="Copiar segredo detectado"
                    >
                      {copiedIndex === finding.id ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>

                  {/* Remediation Guide & Suggested Safe Code */}
                  <div className="bg-[#050505] p-4 border border-[#1A1A1A] text-xs space-y-2.5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-white font-bold uppercase tracking-wider text-[10px]">
                        <Sparkles className="w-3.5 h-3.5 text-[#FF3E00]" />
                        <span>Plano de Remediação:</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleOpenRemediationWiki(finding)}
                        className="text-[10px] font-mono text-[#FF3E00] hover:text-white inline-flex items-center gap-1 font-bold cursor-pointer transition-colors"
                      >
                        <Terminal className="w-3 h-3" />
                        <span>Ver Guia Passo a Passo &rarr;</span>
                      </button>
                    </div>
                    <p className="text-[#AAA] font-mono text-[11px] leading-relaxed">{finding.remediation}</p>

                    <div className="pt-3 border-t border-[#141414] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span className="text-[11px] text-[#888] font-mono truncate mr-2">
                        &gt; SUGESTÃO: <code className="bg-[#141414] px-1.5 py-0.5 text-[#00FF41] border border-[#222]">{getSafeSnippet(finding)}</code>
                      </span>
                      <button
                        onClick={() => handleCopy(getSafeSnippet(finding), `snippet-${finding.id}`)}
                        className="shrink-0 px-3 py-1 text-[10px] font-black uppercase tracking-[0.15em] border border-[#333] hover:border-white text-white hover:bg-white hover:text-black inline-flex items-center gap-1.5 transition-all"
                      >
                        {copiedIndex === `snippet-${finding.id}` ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                        <span>Copiar Código</span>
                      </button>
                    </div>
                  </div>

                  {/* Context-aware In-Depth Technical Explanation */}
                  <SecurityGlossaryInlineCard 
                    finding={finding} 
                    onOpenFullGlossary={onOpenGlossary} 
                  />
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Security Remediation Wiki Modal */}
      <SecurityRemediationWikiModal
        isOpen={isRemediationWikiOpen}
        onClose={() => setIsRemediationWikiOpen(false)}
        initialFinding={selectedWikiFinding}
        findings={safeFindings}
        onNavigateToFileLine={(fileName, line) => {
          const targetFile = safeFiles.find(f => f.path === fileName || f.name === fileName);
          if (targetFile) {
            onSelectFile(targetFile);
          }
        }}
      />

      {/* Paste Code Modal */}
      {showPasteModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0A0A0A] max-w-lg w-full p-6 border border-[#333] space-y-4">
            <div className="flex items-center justify-between border-b border-[#222] pb-3">
              <h3 className="text-xs font-black uppercase tracking-[0.2em] text-white flex items-center gap-2">
                <Code2 className="w-4 h-4 text-[#FF3E00]" />
                <span>Colar Código-Fonte</span>
              </h3>
              <button
                onClick={() => setShowPasteModal(false)}
                className="text-[#666] hover:text-white text-lg font-bold"
              >
                &times;
              </button>
            </div>

            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Nome do Arquivo</label>
              <input
                type="text"
                value={pasteFileName}
                onChange={(e) => setPasteFileName(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
              />
            </div>

            <div>
              <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Código JavaScript ou TypeScript</label>
              <textarea
                rows={8}
                value={pasteContent}
                onChange={(e) => setPasteContent(e.target.value)}
                placeholder="// Cole seu script aqui para escanear...&#10;const apiKey = 'sk-live-1234567890abcdef';"
                className="w-full p-3 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowPasteModal(false)}
                className="px-4 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-[#888] hover:text-white border border-[#222]"
              >
                Cancelar
              </button>
              <button
                onClick={handleCreateCustomFile}
                className="px-5 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-black bg-white hover:bg-[#FF3E00] hover:text-white transition-colors"
              >
                Adicionar e Escanear
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
