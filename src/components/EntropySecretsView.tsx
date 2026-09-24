import React, { useState, useMemo } from 'react';
import { 
  Binary, 
  KeyRound, 
  GitCommit, 
  Sliders, 
  AlertTriangle, 
  ShieldAlert, 
  Eye, 
  EyeOff, 
  Copy, 
  Check, 
  FileCode2, 
  Terminal,
  Search
} from 'lucide-react';
import { ScannedFile } from '../types';
import { scanWorkspaceEntropy, EntropyFinding, GitCommitSecretLeak } from '../lib/entropyScanner';

interface EntropySecretsViewProps {
  files: ScannedFile[];
  onNavigateToFile?: (filePath: string, line?: number) => void;
}

export const EntropySecretsView: React.FC<EntropySecretsViewProps> = ({ files, onNavigateToFile }) => {
  const [entropyThreshold, setEntropyThreshold] = useState<number>(4.2);
  const [revealedIds, setRevealedIds] = useState<Record<string, boolean>>({});
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'WORKSPACE' | 'GIT_HISTORY'>('WORKSPACE');

  const report = useMemo(() => {
    return scanWorkspaceEntropy(files, entropyThreshold);
  }, [files, entropyThreshold]);

  const toggleReveal = (id: string) => {
    setRevealedIds(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6 font-mono">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-pink-500/10 text-pink-400 border border-pink-500/30">
              <Binary className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase">
              Caçador de Segredos por Entropia de Shannon
            </h1>
            <span className="text-[10px] px-2 py-0.5 rounded bg-pink-950/60 text-pink-300 border border-pink-800/60 font-bold">
              H(X) = -Σ P(x) log₂ P(x)
            </span>
          </div>
          <p className="text-xs text-zinc-400 mt-1">
            Detecção matemática de strings aleatórias, chaves privadas, hashes e investigação forense de segredos no histórico Git.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('WORKSPACE')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeTab === 'WORKSPACE'
                ? 'bg-pink-600 text-white border-pink-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            Arquivos do Workspace ({report.highEntropyFindings.length})
          </button>
          <button
            onClick={() => setActiveTab('GIT_HISTORY')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeTab === 'GIT_HISTORY'
                ? 'bg-pink-600 text-white border-pink-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            Histórico Git &amp; Fantasmas ({report.gitHistoryLeaks.length})
          </button>
        </div>
      </div>

      {/* Entropy Metrics & Slider Control */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Slider Card */}
        <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl space-y-3 lg:col-span-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
              <Sliders className="w-3.5 h-3.5 text-pink-400" />
              Limiar de Entropia (Threshold)
            </span>
            <span className="text-sm font-bold text-pink-400">{entropyThreshold.toFixed(1)} bits/char</span>
          </div>
          <input
            type="range"
            min="3.2"
            max="5.6"
            step="0.1"
            value={entropyThreshold}
            onChange={(e) => setEntropyThreshold(parseFloat(e.target.value))}
            className="w-full accent-pink-500 cursor-pointer"
          />
          <div className="flex items-center justify-between text-[10px] text-zinc-500">
            <span>3.2 (Mais sensível)</span>
            <span>4.2 (Padrão Chaves/JWT)</span>
            <span>5.6 (Criptografia Pura)</span>
          </div>
        </div>

        {/* Metric 1 */}
        <div className="bg-[#0C0C0C] border border-[#222] p-4 rounded-xl">
          <span className="text-[10px] text-zinc-400 uppercase tracking-wider block">Tokens Escaneados</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold text-white">{report.totalTokensScanned}</span>
            <span className="text-[10px] text-zinc-500">candidatos</span>
          </div>
          <span className="text-[10px] text-zinc-500 mt-1 block">Entropia Média: {report.averageFileEntropy} bits</span>
        </div>

        {/* Metric 2 */}
        <div className="bg-[#0C0C0C] border border-pink-900/40 p-4 rounded-xl">
          <span className="text-[10px] text-pink-400 uppercase tracking-wider block">Maior Entropia Observada</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className="text-2xl font-bold text-pink-500">{report.highestEntropyObserved}</span>
            <span className="text-[10px] text-pink-400/80">bits/char</span>
          </div>
          <span className="text-[10px] text-pink-400/70 mt-1 block">Alta probabilidade de chave secreta</span>
        </div>
      </div>

      {/* TAB 1: WORKSPACE FINDINGS */}
      {activeTab === 'WORKSPACE' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-zinc-400">
            <span>Tokens com Entropia &gt;= {entropyThreshold.toFixed(1)} bits/char</span>
            <span>{report.highEntropyFindings.length} ocorrências detectadas</span>
          </div>

          {report.highEntropyFindings.length === 0 ? (
            <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500">
              Nenhum token encontrado com entropia superior ao limiar de {entropyThreshold.toFixed(1)} bits/char. Experimente reduzir o controle deslizante para aumentar a sensibilidade.
            </div>
          ) : (
            <div className="space-y-3">
              {report.highEntropyFindings.map(item => {
                const isRevealed = revealedIds[item.id];
                const displayToken = isRevealed ? item.token : item.maskedToken;

                return (
                  <div
                    key={item.id}
                    className="p-4 bg-[#0A0A0A] border border-[#222] hover:border-pink-500/50 rounded-xl space-y-3 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="px-2 py-0.2 rounded text-[10px] font-bold bg-pink-950 text-pink-300 border border-pink-800">
                            {item.entropyLevel} ({item.entropy} bits)
                          </span>
                          <span className="text-xs font-bold text-white">{item.probableType}</span>
                          <span className="text-[10px] text-zinc-500 px-1.5 py-0.2 rounded bg-zinc-800">
                            Charset: {item.charset}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-zinc-400 text-xs">
                          <FileCode2 className="w-3.5 h-3.5 text-zinc-500" />
                          <span>{item.file}:{item.line}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => toggleReveal(item.id)}
                          className="p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors cursor-pointer"
                          title={isRevealed ? "Ocultar segredo" : "Revelar segredo"}
                        >
                          {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                        <button
                          onClick={() => handleCopy(item.token, item.id)}
                          className="p-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors cursor-pointer"
                          title="Copiar token"
                        >
                          {copiedId === item.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>

                    {/* Token & Snippet Box */}
                    <div className="p-2.5 bg-black rounded-lg border border-white/5 space-y-1 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-zinc-500">Token Detectado:</span>
                        <span className="text-[10px] text-pink-400 font-bold">{item.token.length} caracteres</span>
                      </div>
                      <code className="text-pink-300 block truncate font-bold text-[11px]">{displayToken}</code>
                    </div>

                    <p className="text-[11px] text-zinc-400">{item.recommendation}</p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: GIT COMMIT HISTORY DIGGER */}
      {activeTab === 'GIT_HISTORY' && (
        <div className="space-y-4">
          <div className="p-4 bg-amber-950/20 border border-amber-900/40 rounded-xl flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-xs text-amber-200/90 leading-relaxed">
              <strong className="text-white block mb-1">Aviso sobre Segredos Fantasmas em Histórico Git:</strong>
              Mesmo que um segredo seja removido do código atual (HEAD), se ele foi commitado em qualquer commit anterior, qualquer clone do repositório pode extraí-lo facilmente via `git log -p` ou desempacotando arquivos pack. Para sanar o risco, é obrigatório reescrever o histórico com ferramentas especializadas.
            </div>
          </div>

          <div className="space-y-3">
            {report.gitHistoryLeaks.length === 0 ? (
              <div className="p-12 text-center bg-black/40 border border-dashed border-[#222] rounded-xl space-y-2">
                <Check className="w-8 h-8 text-emerald-400 mx-auto" />
                <h3 className="text-sm font-bold text-white">Nenhum segredo no histórico Git</h3>
                <p className="text-xs text-zinc-500 max-w-md mx-auto">
                  Nenhum commit com credenciais ou chaves residuais detectado. O repositório está limpo.
                </p>
              </div>
            ) : (
              report.gitHistoryLeaks.map((leak, idx) => (
              <div key={idx} className="p-4 bg-[#0A0A0A] border border-rose-900/40 rounded-xl space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2 py-0.2 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-800">
                        {leak.dangerLevel}
                      </span>
                      <span className="px-2 py-0.2 rounded text-[10px] bg-zinc-800 text-zinc-300">
                        Commit: {leak.commitHash}
                      </span>
                      <span className="text-xs text-zinc-400">{leak.date}</span>
                    </div>
                    <h3 className="font-bold text-sm text-white">{leak.commitMessage}</h3>
                    <span className="text-xs text-zinc-500">Autor: {leak.author} | Arquivo: {leak.file}</span>
                  </div>

                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    leak.statusInHead.includes('DELETED') ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                  }`}>
                    {leak.statusInHead === 'DELETED_FROM_HEAD_BUT_LEAKED_IN_GIT_HISTORY' ? 'Apagado do HEAD, mas no Git' : 'Presente no Código'}
                  </span>
                </div>

                <div className="p-2.5 bg-black rounded-lg border border-white/5 space-y-1 text-xs">
                  <span className="text-[10px] text-zinc-500 block">Segredo Vazado no Commit:</span>
                  <code className="text-rose-400 font-bold block">{leak.maskedSecret}</code>
                </div>

                {/* Git remediation command */}
                <div className="p-3 bg-zinc-900/70 rounded-lg border border-zinc-800 space-y-1 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-zinc-400 uppercase font-bold flex items-center gap-1">
                      <Terminal className="w-3 h-3 text-emerald-400" />
                      Comando de Limpeza de Histórico (git-filter-repo / BFG):
                    </span>
                    <button
                      onClick={() => handleCopy(leak.gitRemediationCommand, `cmd-${idx}`)}
                      className="text-[10px] text-emerald-400 hover:underline cursor-pointer flex items-center gap-1"
                    >
                      {copiedId === `cmd-${idx}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedId === `cmd-${idx}` ? 'Copiado' : 'Copiar'}</span>
                    </button>
                  </div>
                  <code className="text-emerald-300 block text-[11px] overflow-x-auto">
                    {leak.gitRemediationCommand}
                  </code>
                </div>
              </div>
            )))}
          </div>
        </div>
      )}
    </div>
  );
};
