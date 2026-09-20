import React, { useState, useMemo } from 'react';
import { 
  Crosshair, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Play, 
  Terminal, 
  ShieldCheck, 
  Copy, 
  Check, 
  RefreshCw,
  Globe,
  Sliders,
  Send
} from 'lucide-react';
import { ApiEndpointFinding } from '../types';
import { 
  AttackCategory, 
  FuzzingPayload, 
  FuzzingTestResult, 
  BUILTIN_FUZZING_PAYLOADS, 
  auditSecurityHeaders, 
  simulateFuzzingTest 
} from '../lib/dastSimulator';

interface DastFuzzerViewProps {
  endpoints: ApiEndpointFinding[];
}

export const DastFuzzerView: React.FC<DastFuzzerViewProps> = ({ endpoints }) => {
  const [activeSubTab, setActiveSubTab] = useState<'FUZZER' | 'HEADERS'>('FUZZER');
  
  // Fuzzer State
  const defaultEndpoint = endpoints.length > 0 ? endpoints[0].path : '/api/v1/payments/charge';
  const [targetEndpoint, setTargetEndpoint] = useState(defaultEndpoint);
  const [httpMethod, setHttpMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE'>('POST');
  const [selectedCategory, setSelectedCategory] = useState<AttackCategory>('SQL_INJECTION');
  const [selectedPayloadId, setSelectedPayloadId] = useState<string>(BUILTIN_FUZZING_PAYLOADS[0].id);
  const [customPayloadText, setCustomPayloadText] = useState('');
  const [isRunningFuzz, setIsRunningFuzz] = useState(false);
  const [testHistory, setTestHistory] = useState<FuzzingTestResult[]>([]);
  const [copiedCode, setCopiedCode] = useState(false);

  // Headers Audit State (simulated default baseline headers)
  const [customHeaders, setCustomHeaders] = useState<Record<string, string>>({
    'x-content-type-options': 'nosniff',
    'access-control-allow-origin': '*'
  });

  const headersAudit = useMemo(() => {
    return auditSecurityHeaders(customHeaders);
  }, [customHeaders]);

  const availablePayloads = useMemo(() => {
    return BUILTIN_FUZZING_PAYLOADS.filter(p => p.category === selectedCategory);
  }, [selectedCategory]);

  const currentPayload = useMemo(() => {
    return availablePayloads.find(p => p.id === selectedPayloadId) || availablePayloads[0] || BUILTIN_FUZZING_PAYLOADS[0];
  }, [availablePayloads, selectedPayloadId]);

  const handleRunFuzzTest = () => {
    setIsRunningFuzz(true);
    setTimeout(() => {
      const activePayload: FuzzingPayload = customPayloadText.trim() ? {
        ...currentPayload,
        payload: customPayloadText
      } : currentPayload;

      const result = simulateFuzzingTest(targetEndpoint, httpMethod, activePayload);
      setTestHistory(prev => [result, ...prev]);
      setIsRunningFuzz(false);
    }, 400);
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      {/* Header & Sub-Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#222] pb-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <Crosshair className="w-5 h-5" />
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white uppercase font-mono">
              DAST &amp; API Security Fuzzer
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-bold">
              Dynamic Application Security Testing
            </span>
          </div>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Simulação dinâmica de ataques em endpoints descobertos (SQLi, XSS, SSRF) e auditoria de cabeçalhos HTTP.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono">
          <button
            onClick={() => setActiveSubTab('FUZZER')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeSubTab === 'FUZZER'
                ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            Fuzzer de Endpoints
          </button>
          <button
            onClick={() => setActiveSubTab('HEADERS')}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer border ${
              activeSubTab === 'HEADERS'
                ? 'bg-emerald-600 text-white border-emerald-500 shadow'
                : 'bg-[#141414] text-zinc-400 border-[#2A2A2A] hover:text-white'
            }`}
          >
            Cabeçalhos HTTP ({headersAudit.grade})
          </button>
        </div>
      </div>

      {/* SUBTAB 1: DAST FUZZER */}
      {activeSubTab === 'FUZZER' && (
        <div className="space-y-6">
          {/* Target Endpoint & Payload Selection Box */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 space-y-4 font-mono">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Endpoint Selector */}
              <div className="md:col-span-2 space-y-1">
                <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                  Endpoint Alvo (Descoberto pelo LinkFinder):
                </label>
                <div className="flex items-center gap-2">
                  <select
                    value={httpMethod}
                    onChange={(e) => setHttpMethod(e.target.value as any)}
                    className="bg-black/60 border border-[#2A2A2A] px-2.5 py-2 rounded-lg text-xs font-bold text-emerald-400 focus:outline-none"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                  <input
                    type="text"
                    value={targetEndpoint}
                    onChange={(e) => setTargetEndpoint(e.target.value)}
                    placeholder="/api/v1/resource"
                    className="flex-1 bg-black/60 border border-[#2A2A2A] px-3 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              {/* Attack Class Selector */}
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                  Classe de Ataque:
                </label>
                <select
                  value={selectedCategory}
                  onChange={(e) => {
                    setSelectedCategory(e.target.value as AttackCategory);
                    setCustomPayloadText('');
                  }}
                  className="w-full bg-black/60 border border-[#2A2A2A] px-3 py-2 rounded-lg text-xs text-white focus:outline-none focus:border-emerald-500"
                >
                  <option value="SQL_INJECTION">SQL Injection (SQLi)</option>
                  <option value="NOSQL_INJECTION">NoSQL Injection (MongoDB)</option>
                  <option value="XSS">Cross-Site Scripting (XSS)</option>
                  <option value="PATH_TRAVERSAL">Path Traversal (/etc/passwd)</option>
                  <option value="SSRF">Server-Side Request Forgery</option>
                  <option value="COMMAND_INJECTION">Command Injection (Bash)</option>
                </select>
              </div>
            </div>

            {/* Payloads Selector */}
            <div className="space-y-2 pt-2 border-t border-white/5">
              <label className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block">
                Payload de Fuzzing:
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {availablePayloads.map(payload => (
                  <button
                    key={payload.id}
                    onClick={() => {
                      setSelectedPayloadId(payload.id);
                      setCustomPayloadText('');
                    }}
                    className={`p-2.5 rounded-lg border text-left text-xs transition-all cursor-pointer ${
                      currentPayload.id === payload.id && !customPayloadText
                        ? 'bg-[#181818] border-emerald-500 text-white shadow'
                        : 'bg-black/40 border-[#222] text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-emerald-400">{payload.name}</span>
                      <span className="text-[9px] text-zinc-500">{payload.cwe}</span>
                    </div>
                    <code className="text-[10.5px] text-zinc-300 block truncate mt-1">{payload.payload}</code>
                  </button>
                ))}
              </div>

              {/* Action Button */}
              <div className="pt-2 flex items-center justify-between">
                <span className="text-[11px] text-zinc-500">
                  Alvo atual: <code className="text-zinc-300">{httpMethod} {targetEndpoint}</code>
                </span>
                <button
                  onClick={handleRunFuzzTest}
                  disabled={isRunningFuzz}
                  className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider flex items-center gap-2 transition-colors cursor-pointer shadow"
                >
                  <Send className={`w-3.5 h-3.5 ${isRunningFuzz ? 'animate-bounce' : ''}`} />
                  <span>{isRunningFuzz ? 'Injetando Payload...' : 'Disparar Fuzzing de Teste'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Test Execution Results Stream */}
          <div className="space-y-3 font-mono">
            <h3 className="text-xs font-bold text-zinc-400 uppercase tracking-wider">
              Histórico de Testes de Fuzzing ({testHistory.length})
            </h3>

            {testHistory.length === 0 ? (
              <div className="p-8 text-center bg-[#0C0C0C] border border-[#222] rounded-xl text-xs text-zinc-500">
                Nenhum teste dinâmico executado nesta sessão. Clique em &quot;Disparar Fuzzing de Teste&quot; acima para simular os ataques defensivos.
              </div>
            ) : (
              testHistory.map(test => {
                const isVuln = test.verdict === 'VULNERABLE';
                const isWaf = test.verdict === 'BLOCKED_BY_WAF';
                const isSafe = test.verdict === 'SAFE' || test.verdict === 'SANITIZED';

                return (
                  <div
                    key={test.id}
                    className={`p-4 rounded-xl border transition-all ${
                      isVuln
                        ? 'bg-[#0E0708] border-rose-900/50'
                        : isWaf
                        ? 'bg-[#0E0B07] border-amber-900/40'
                        : 'bg-[#070E0A] border-emerald-900/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-0.2 rounded text-[10px] font-bold uppercase tracking-wider ${
                            isVuln
                              ? 'bg-rose-600 text-white animate-pulse'
                              : isWaf
                              ? 'bg-amber-600 text-white'
                              : 'bg-emerald-600 text-white'
                          }`}>
                            {test.verdict}
                          </span>
                          <span className="text-xs font-bold text-white">{test.method} {test.endpoint}</span>
                          <span className="text-[10px] text-zinc-500">({test.simulatedResponseTimeMs}ms)</span>
                          <span className="text-[10px] text-zinc-500">HTTP {test.simulatedStatus}</span>
                        </div>
                        <p className="text-[11px] text-zinc-300">{test.analysis}</p>
                      </div>

                      <span className="text-[10px] text-zinc-500 shrink-0">{test.timestamp}</span>
                    </div>

                    <div className="mt-3 pt-2.5 border-t border-white/5 space-y-1.5 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-zinc-500">Payload enviado:</span>
                        <code className="px-2 py-0.5 rounded bg-black/60 text-zinc-300 text-[10.5px]">
                          {test.payload.payload}
                        </code>
                      </div>
                      <div className="p-2.5 rounded bg-black/80 text-zinc-400 text-[10.5px] overflow-x-auto">
                        <span className="text-zinc-600 select-none block mb-1">Resposta do Servidor:</span>
                        <code>{test.responseSnippet}</code>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* SUBTAB 2: HTTP SECURITY HEADERS AUDITOR */}
      {activeSubTab === 'HEADERS' && (
        <div className="space-y-6 font-mono">
          {/* Grade Card */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-[10px] font-bold text-zinc-500 uppercase tracking-wider block">Nota de Cabeçalhos HTTP</span>
              <h2 className="text-2xl font-bold text-white">Auditoria OWASP Secure Headers</h2>
              <p className="text-xs text-zinc-400">Proteção contra XSS, Clickjacking, MIME-sniffing e downgrade de SSL.</p>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right">
                <span className="text-xs text-zinc-500 block">Pontuação</span>
                <span className="text-xl font-bold text-white">{headersAudit.score}/100</span>
              </div>
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center font-bold text-2xl border-2 ${
                headersAudit.grade === 'A+' || headersAudit.grade === 'A'
                  ? 'bg-emerald-950/40 text-emerald-400 border-emerald-500'
                  : headersAudit.grade === 'B' || headersAudit.grade === 'C'
                  ? 'bg-amber-950/40 text-amber-400 border-amber-500'
                  : 'bg-rose-950/40 text-rose-500 border-rose-500'
              }`}>
                {headersAudit.grade}
              </div>
            </div>
          </div>

          {/* Headers Checklist */}
          <div className="space-y-3">
            {headersAudit.headers.map(header => {
              const isPresent = header.status === 'PRESENT';
              const isWeak = header.status === 'WEAK';

              return (
                <div
                  key={header.header}
                  className={`p-4 rounded-xl border ${
                    isPresent
                      ? 'bg-[#070E0A] border-emerald-900/40'
                      : isWeak
                      ? 'bg-[#0E0B07] border-amber-900/40'
                      : 'bg-[#0E0708] border-rose-900/40'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-white">{header.header}</span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                          isPresent ? 'bg-emerald-900 text-emerald-200' : isWeak ? 'bg-amber-900 text-amber-200' : 'bg-rose-900 text-rose-200'
                        }`}>
                          {header.status}
                        </span>
                        <span className="text-[10px] text-zinc-500">{header.importance}</span>
                      </div>
                      <p className="text-xs text-zinc-400">{header.description}</p>
                    </div>

                    <span className="text-[10px] text-zinc-500 shrink-0">{header.cwe}</span>
                  </div>

                  <div className="mt-3 pt-2.5 border-t border-white/5 space-y-1 text-xs">
                    {header.currentValue && (
                      <div className="text-[11px] text-zinc-400">
                        <span className="text-zinc-500">Valor Atual: </span>
                        <code>{header.currentValue}</code>
                      </div>
                    )}
                    <div className="text-[11px] text-emerald-400">
                      <span className="text-zinc-500">Valor Recomendado: </span>
                      <code>{header.recommendedValue}</code>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Remediation Snippet */}
          <div className="bg-[#0C0C0C] border border-[#222] rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider">
                Middleware Recomendado para Nota A+ (Helmet / Express):
              </span>
              <button
                onClick={() => handleCopyCode(headersAudit.recommendedMiddlewareCode)}
                className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCode ? 'Copiado!' : 'Copiar Snippet'}</span>
              </button>
            </div>
            <pre className="p-3 bg-black rounded-lg text-emerald-300 text-xs overflow-x-auto border border-white/5">
              <code>{headersAudit.recommendedMiddlewareCode}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
