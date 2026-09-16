import React, { useState, useEffect } from 'react';
import { 
  FlaskConical, 
  Play, 
  CheckCircle2, 
  XCircle, 
  Clock, 
  Download, 
  Upload, 
  Trash2, 
  RotateCcw, 
  FileJson, 
  ExternalLink, 
  Check, 
  Copy, 
  Eye, 
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Tag,
  ShieldCheck
} from 'lucide-react';
import { RegexUnitTestCase, RegexTestSuiteSummary } from '../types';
import { 
  loadUnitTests, 
  saveUnitTests, 
  deleteUnitTest, 
  runSingleUnitTest, 
  runAllUnitTests, 
  exportUnitTestsJson, 
  importUnitTestsJson, 
  DEFAULT_UNIT_TEST_CASES 
} from '../lib/regexUnitTestManager';
import { safeCopyText } from '../lib/storage';

interface RegexUnitTestLibraryProps {
  onLoadTestCaseToSandbox: (testCase: RegexUnitTestCase) => void;
  onClose?: () => void;
}

export const RegexUnitTestLibrary: React.FC<RegexUnitTestLibraryProps> = ({
  onLoadTestCaseToSandbox,
  onClose
}) => {
  const [testCases, setTestCases] = useState<RegexUnitTestCase[]>([]);
  const [summary, setSummary] = useState<RegexTestSuiteSummary | null>(null);
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [runningTestId, setRunningTestId] = useState<string | null>(null);
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);
  const [showJsonViewer, setShowJsonViewer] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importJsonText, setImportJsonText] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  // Load from storage on mount
  useEffect(() => {
    refreshTests();
  }, []);

  const refreshTests = () => {
    const loaded = loadUnitTests();
    setTestCases(loaded);
    computeSummary(loaded);
  };

  const computeSummary = (tests: RegexUnitTestCase[]) => {
    const passed = tests.filter(t => t.lastRunStatus === 'PASSED').length;
    const failed = tests.filter(t => t.lastRunStatus === 'FAILED').length;
    const pending = tests.filter(t => !t.lastRunStatus || t.lastRunStatus === 'PENDING').length;
    const total = tests.length;
    const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;

    setSummary({
      totalTests: total,
      passedCount: passed,
      failedCount: failed,
      pendingCount: pending,
      passRatePercentage: passRate
    });
  };

  const showNotification = (msg: string) => {
    setActionSuccessMsg(msg);
    setTimeout(() => setActionSuccessMsg(null), 3000);
  };

  // Run all unit tests
  const handleRunAll = () => {
    setIsRunningAll(true);
    setTimeout(() => {
      const { updatedTests, summary: newSummary } = runAllUnitTests(testCases);
      setTestCases(updatedTests);
      setSummary(newSummary);
      setIsRunningAll(false);
      showNotification(`Execução concluída: ${newSummary.passedCount}/${newSummary.totalTests} testes aprovados.`);
    }, 150);
  };

  // Run single unit test
  const handleRunSingle = (testCase: RegexUnitTestCase) => {
    setRunningTestId(testCase.id);
    setTimeout(() => {
      const res = runSingleUnitTest(testCase);
      const updated: RegexUnitTestCase = {
        ...testCase,
        lastRunStatus: res.status,
        lastRunMessage: res.message,
        lastRunAt: new Date().toISOString(),
        lastActualCount: res.actualCount,
        lastActualMatches: res.actualMatches
      };

      const newTests = testCases.map(t => t.id === testCase.id ? updated : t);
      setTestCases(newTests);
      saveUnitTests(newTests);
      computeSummary(newTests);
      setRunningTestId(null);
    }, 100);
  };

  // Delete test case
  const handleDelete = (id: string, name: string) => {
    const updated = deleteUnitTest(id);
    setTestCases(updated);
    computeSummary(updated);
    showNotification(`Caso de teste "${name}" removido.`);
  };

  // Reset to default
  const handleResetDefaults = () => {
    saveUnitTests(DEFAULT_UNIT_TEST_CASES);
    setTestCases(DEFAULT_UNIT_TEST_CASES);
    computeSummary(DEFAULT_UNIT_TEST_CASES);
    showNotification('Biblioteca restaurada para os casos de teste padrão.');
  };

  // Export JSON file
  const handleExportJson = () => {
    const jsonStr = exportUnitTestsJson(testCases);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secscan-regex-unit-tests-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotification('Arquivo JSON exportado com sucesso.');
  };

  // Copy JSON to clipboard
  const handleCopyJson = async () => {
    const jsonStr = exportUnitTestsJson(testCases);
    const ok = await safeCopyText(jsonStr);
    if (ok) {
      setCopiedJson(true);
      setTimeout(() => setCopiedJson(false), 2000);
    }
  };

  // Import JSON
  const handleImportSubmit = () => {
    if (!importJsonText.trim()) return;
    const result = importUnitTestsJson(importJsonText);
    if (!result.success) {
      setImportError(result.error || 'Erro na importação.');
      return;
    }

    setTestCases(result.tests);
    computeSummary(result.tests);
    setImportModalOpen(false);
    setImportJsonText('');
    setImportError(null);
    showNotification(`${result.importedCount} casos de teste importados com sucesso.`);
  };

  // File upload reader
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        setImportJsonText(content);
        setImportModalOpen(true);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  return (
    <div className="bg-[#080808] border border-[#222] p-5 space-y-5 animate-in fade-in duration-200">
      {/* Toast Notification */}
      {actionSuccessMsg && (
        <div className="p-3 bg-[#00FF41]/10 border border-[#00FF41] text-[#00FF41] text-xs font-mono font-bold flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#00FF41]" />
            <span>{actionSuccessMsg}</span>
          </div>
          <button onClick={() => setActionSuccessMsg(null)} className="text-[#888] hover:text-white cursor-pointer">&times;</button>
        </div>
      )}

      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 bg-[#FF3E00] text-white flex items-center justify-center font-black">
              <FlaskConical className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-black uppercase tracking-[0.2em] text-white flex items-center gap-2">
                <span>Biblioteca de Testes Unitários de Regressão</span>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-[#141414] border border-[#333] text-[#888] font-normal">
                  JSON PERSISTENTE
                </span>
              </h3>
              <p className="text-xs font-mono text-[#888]">
                Conjunto de suítes e asserções gravadas para blindar regras regex contra falsos negativos e desvios de sintaxe.
              </p>
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={handleRunAll}
            disabled={isRunningAll || testCases.length === 0}
            className="px-3.5 py-2 bg-[#00FF41] hover:bg-white text-black font-black uppercase text-[10px] tracking-wider flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(0,255,65,0.2)] disabled:opacity-40 cursor-pointer"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${isRunningAll ? 'animate-spin' : ''}`} />
            <span>{isRunningAll ? 'Executando Suíte...' : 'Executar Todos os Testes'}</span>
          </button>

          <button
            type="button"
            onClick={() => setShowJsonViewer(!showJsonViewer)}
            className={`px-3 py-2 border text-[10px] font-mono uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer ${
              showJsonViewer ? 'bg-white text-black border-white' : 'bg-[#111] text-zinc-300 border-[#333] hover:border-white'
            }`}
          >
            <FileJson className="w-3.5 h-3.5" />
            <span>Ver JSON</span>
          </button>

          <label className="px-3 py-2 bg-[#111] hover:bg-[#222] text-zinc-300 hover:text-white border border-[#333] text-[10px] font-mono uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer">
            <Upload className="w-3.5 h-3.5" />
            <span>Importar JSON</span>
            <input type="file" accept=".json" onChange={handleFileUpload} className="hidden" />
          </label>

          <button
            type="button"
            onClick={handleExportJson}
            className="px-3 py-2 bg-[#111] hover:bg-[#222] text-zinc-300 hover:text-white border border-[#333] text-[10px] font-mono uppercase font-bold flex items-center gap-1.5 transition-colors cursor-pointer"
            title="Download do arquivo JSON da suíte"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exportar</span>
          </button>

          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className="px-2.5 py-2 text-[#888] hover:text-white border border-[#222] text-xs font-bold cursor-pointer"
              title="Recolher Biblioteca"
            >
              &times;
            </button>
          )}
        </div>
      </div>

      {/* Metrics Summary Strip */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#040404] p-3 border border-[#1A1A1A]">
          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-white" />
            <div>
              <div className="text-[10px] font-mono text-[#777] uppercase">Total de Testes</div>
              <div className="text-base font-black font-mono text-white">{summary.totalTests}</div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-[#00FF41]" />
            <div>
              <div className="text-[10px] font-mono text-[#777] uppercase">Testes Aprovados</div>
              <div className="text-base font-black font-mono text-[#00FF41]">{summary.passedCount}</div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-[#FF3E00]" />
            <div>
              <div className="text-[10px] font-mono text-[#777] uppercase">Falhas de Regressão</div>
              <div className="text-base font-black font-mono text-[#FF3E00]">{summary.failedCount}</div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <span className="w-2 h-2 rounded-full bg-[#FF7A00]" />
            <div>
              <div className="text-[10px] font-mono text-[#777] uppercase">Taxa de Estabilidade</div>
              <div className="text-base font-black font-mono text-[#FF7A00]">{summary.passRatePercentage}%</div>
            </div>
          </div>
        </div>
      )}

      {/* Raw JSON Viewer Panel (Collapsible) */}
      {showJsonViewer && (
        <div className="p-4 bg-[#050505] border border-[#252525] space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#1E1E1E]">
            <span className="text-xs font-mono font-bold text-zinc-300 flex items-center gap-2">
              <FileJson className="w-4 h-4 text-[#00FF41]" />
              <span>secscan_regex_unit_test_cases.json (Persistent Storage Payload)</span>
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopyJson}
                className="px-2.5 py-1 text-[10px] font-mono uppercase bg-[#141414] hover:bg-[#222] text-zinc-300 border border-[#333] flex items-center gap-1 cursor-pointer"
              >
                {copiedJson ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                <span>{copiedJson ? 'Copiado!' : 'Copiar JSON'}</span>
              </button>
              <button
                type="button"
                onClick={handleResetDefaults}
                className="px-2.5 py-1 text-[10px] font-mono uppercase bg-[#141414] hover:bg-[#222] text-[#888] hover:text-[#FF3E00] border border-[#333] flex items-center gap-1 cursor-pointer"
                title="Redefinir para casos de teste padrão"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Restaurar Padrões</span>
              </button>
            </div>
          </div>

          <pre className="p-3 bg-[#000] border border-[#1A1A1A] font-mono text-xs text-[#00FF41] max-h-60 overflow-auto whitespace-pre">
            {exportUnitTestsJson(testCases)}
          </pre>
        </div>
      )}

      {/* Test Cases Table / List */}
      {testCases.length === 0 ? (
        <div className="p-8 text-center bg-[#050505] border border-dashed border-[#222] space-y-3">
          <FlaskConical className="w-8 h-8 text-[#444] mx-auto" />
          <p className="text-xs font-mono text-[#888]">
            Nenhum caso de teste unitário cadastrado na biblioteca.
          </p>
          <button
            type="button"
            onClick={handleResetDefaults}
            className="px-3 py-1.5 text-[10px] font-mono uppercase bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors cursor-pointer"
          >
            Carregar Casos de Teste Padrão
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="space-y-2">
            {testCases.map((test) => {
              const isExpanded = expandedTestId === test.id;
              const isRunningThis = runningTestId === test.id;

              let statusColor = 'text-[#888] bg-[#111] border-[#333]';
              let StatusIcon = Clock;
              if (test.lastRunStatus === 'PASSED') {
                statusColor = 'text-[#00FF41] bg-[#00FF41]/10 border-[#00FF41]/40';
                StatusIcon = CheckCircle2;
              } else if (test.lastRunStatus === 'FAILED') {
                statusColor = 'text-[#FF3E00] bg-[#FF3E00]/10 border-[#FF3E00]/40';
                StatusIcon = XCircle;
              }

              return (
                <div 
                  key={test.id} 
                  className={`border transition-colors ${
                    isExpanded ? 'bg-[#0A0A0A] border-[#333]' : 'bg-[#050505] border-[#1E1E1E] hover:border-[#2A2A2A]'
                  }`}
                >
                  {/* Test Item Header Row */}
                  <div className="p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="flex items-start md:items-center gap-3 flex-1 min-w-0">
                      {/* Status indicator */}
                      <span className={`px-2 py-1 text-[9px] font-mono font-bold uppercase border flex items-center gap-1 shrink-0 ${statusColor}`}>
                        <StatusIcon className="w-3 h-3" />
                        <span>{test.lastRunStatus || 'PENDENTE'}</span>
                      </span>

                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-xs font-bold text-white tracking-wide truncate">
                            {test.name}
                          </span>
                          {test.category && (
                            <span className="text-[9px] font-mono px-1.5 py-0.2 bg-[#141414] text-zinc-400 border border-[#2A2A2A]">
                              {test.category}
                            </span>
                          )}
                          {test.severity && (
                            <span className={`text-[9px] font-mono px-1.5 py-0.2 font-bold ${
                              test.severity === 'CRITICAL' ? 'text-[#FF3E00]' : 'text-[#FF7A00]'
                            }`}>
                              {test.severity}
                            </span>
                          )}
                        </div>

                        {/* Pattern snippet */}
                        <div className="flex items-center gap-2 mt-1">
                          <code className="text-[11px] font-mono text-[#00FF41] truncate bg-[#000] px-2 py-0.5 border border-[#1A1A1A] max-w-md">
                            /{test.pattern}/{test.flags}
                          </code>
                          <span className="text-[10px] font-mono text-[#666]">
                            Asserção: {test.expectedMatchCount} match(es) esperados
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Test Item Actions */}
                    <div className="flex items-center gap-2 shrink-0 self-end md:self-auto">
                      <button
                        type="button"
                        onClick={() => handleRunSingle(test)}
                        disabled={isRunningThis}
                        className="px-2.5 py-1.5 text-[10px] font-mono uppercase bg-[#141414] hover:bg-[#222] text-white border border-[#333] flex items-center gap-1 transition-colors cursor-pointer"
                        title="Executar este caso de teste agora"
                      >
                        <Play className={`w-3 h-3 fill-current ${isRunningThis ? 'animate-spin' : ''}`} />
                        <span>{isRunningThis ? 'Rodando...' : 'Testar'}</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => onLoadTestCaseToSandbox(test)}
                        className="px-2.5 py-1.5 text-[10px] font-mono uppercase bg-[#00FF41]/10 hover:bg-[#00FF41] text-[#00FF41] hover:text-black border border-[#00FF41]/40 transition-colors flex items-center gap-1 cursor-pointer"
                        title="Carregar regex e texto no Sandbox editável"
                      >
                        <ExternalLink className="w-3 h-3" />
                        <span>No Sandbox</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setExpandedTestId(isExpanded ? null : test.id)}
                        className="px-2 py-1.5 text-[#888] hover:text-white border border-[#222] cursor-pointer"
                        title={isExpanded ? 'Recolher detalhes' : 'Expandir detalhes e payload'}
                      >
                        {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5 text-zinc-300" />}
                      </button>

                      <button
                        type="button"
                        onClick={() => handleDelete(test.id, test.name)}
                        className="p-1.5 text-[#666] hover:text-[#FF3E00] transition-colors cursor-pointer"
                        title="Excluir este caso de teste"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Test Details */}
                  {isExpanded && (
                    <div className="p-4 bg-[#000] border-t border-[#1E1E1E] space-y-3 font-mono text-xs text-zinc-300">
                      {test.description && (
                        <p className="text-[11px] text-[#888]">
                          {test.description}
                        </p>
                      )}

                      {/* Execution feedback message */}
                      {test.lastRunMessage && (
                        <div className={`p-2.5 border text-xs ${
                          test.lastRunStatus === 'PASSED'
                            ? 'bg-[#00FF41]/5 border-[#00FF41]/30 text-[#00FF41]'
                            : 'bg-[#FF3E00]/5 border-[#FF3E00]/30 text-[#FF3E00]'
                        }`}>
                          <span className="font-bold">Resultado da Execução:</span> {test.lastRunMessage}
                        </div>
                      )}

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {/* Expected Matches */}
                        <div>
                          <div className="text-[10px] uppercase text-[#777] mb-1">Asserções de Matches Esperados:</div>
                          <div className="p-2 bg-[#080808] border border-[#1A1A1A] space-y-1">
                            <div>Contagem: <strong className="text-white">{test.expectedMatchCount}</strong></div>
                            {test.expectedMatches && test.expectedMatches.length > 0 && (
                              <div className="space-y-0.5 mt-1">
                                {test.expectedMatches.map((m, idx) => (
                                  <div key={idx} className="text-[#00FF41] text-[10px] break-all">
                                    #{idx + 1}: {m}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Test Input Preview */}
                        <div>
                          <div className="text-[10px] uppercase text-[#777] mb-1">Texto de Entrada Salvo (Test Input):</div>
                          <pre className="p-2 bg-[#080808] border border-[#1A1A1A] text-[10px] text-zinc-400 max-h-32 overflow-auto whitespace-pre-wrap">
                            {test.testInput}
                          </pre>
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-[#555] pt-2 border-t border-[#1A1A1A]">
                        <span>ID: {test.id}</span>
                        <span>Criado em: {new Date(test.createdAt).toLocaleString()}</span>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Manual JSON Import Modal */}
      {importModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0A0A0A] max-w-xl w-full p-5 border border-[#333] space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#222]">
              <h4 className="text-xs font-black uppercase tracking-[0.2em] text-white flex items-center gap-2">
                <Upload className="w-4 h-4 text-[#00FF41]" />
                <span>Importar Casos de Teste (JSON)</span>
              </h4>
              <button 
                onClick={() => setImportModalOpen(false)} 
                className="text-[#666] hover:text-white text-lg font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            {importError && (
              <div className="p-2 bg-[#FF3E00]/10 border border-[#FF3E00] text-[#FF3E00] text-xs font-mono">
                {importError}
              </div>
            )}

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Cole o conteúdo JSON da suíte de testes:
              </label>
              <textarea
                rows={10}
                value={importJsonText}
                onChange={(e) => setImportJsonText(e.target.value)}
                placeholder='[{"id":"test-1","name":"My Test","pattern":"(?<key>[A-Z0-9_]{16,32})","flags":"g","testInput":"EXAMPLE_CREDENTIAL_KEY_VAL","expectedMatchCount":1}]'
                className="w-full p-3 bg-[#050505] border border-[#222] text-[#00FF41] font-mono text-xs focus:outline-none focus:border-[#00FF41]"
              />
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-[#222]">
              <button
                type="button"
                onClick={() => setImportModalOpen(false)}
                className="px-3 py-1.5 text-[10px] font-mono uppercase text-[#888] hover:text-white border border-[#222] cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleImportSubmit}
                disabled={!importJsonText.trim()}
                className="px-4 py-1.5 text-[10px] font-black uppercase tracking-wider text-black bg-[#00FF41] hover:bg-white transition-colors disabled:opacity-40 cursor-pointer"
              >
                Confirmar Importação
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
