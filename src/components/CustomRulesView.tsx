import React, { useState } from 'react';
import { 
  SlidersHorizontal, 
  Plus, 
  Check, 
  Trash2, 
  Sparkles, 
  Code, 
  Download, 
  Upload, 
  AlertCircle,
  HelpCircle,
  Tag,
  Wrench,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
  Terminal
} from 'lucide-react';
import { RegexRule, FindingCategory, SeverityLevel } from '../types';
import { RegexRuleBuilder } from './RegexRuleBuilder';
import { RegexSandbox } from './RegexSandbox';

interface CustomRulesViewProps {
  rules: RegexRule[];
  onToggleRule: (ruleId: string) => void;
  onAddRule: (rule: RegexRule) => void;
  onDeleteRule: (ruleId: string) => void;
  onExportRules: () => void;
  onImportRules: (rules: RegexRule[]) => void;
}

export const CustomRulesView: React.FC<CustomRulesViewProps> = ({
  rules,
  onToggleRule,
  onAddRule,
  onDeleteRule,
  onExportRules,
  onImportRules
}) => {
  const [showAddModal, setShowAddModal] = useState(false);
  const [modalTab, setModalTab] = useState<'visual' | 'manual' | 'sandbox'>('visual');
  const [isBuilderOpen, setIsBuilderOpen] = useState(false);
  const [isSandboxOpen, setIsSandboxOpen] = useState(true);

  // Sandbox current active state to allow passing patterns across builder/sandbox
  const [sandboxPattern, setSandboxPattern] = useState('(?<prefix>AKIA|ASIA|sk_live_|ghp_)(?<token>[0-9A-Za-z_]{16,40})');
  const [sandboxFlags, setSandboxFlags] = useState('g');
  const [sandboxText, setSandboxText] = useState<string | undefined>(undefined);

  // New rule form state
  const [name, setName] = useState('');
  const [pattern, setPattern] = useState('');
  const [flags, setFlags] = useState('g');
  const [category, setCategory] = useState<FindingCategory>('CUSTOM_REGEX');
  const [severity, setSeverity] = useState<SeverityLevel>('HIGH');
  const [description, setDescription] = useState('');
  const [remediation, setRemediation] = useState('');
  const [minEntropy, setMinEntropy] = useState<number>(3.5);
  const [exampleMatch, setExampleMatch] = useState('');

  // Live Tester state
  const [testPattern, setTestPattern] = useState('\\bTOKEN-[A-Z0-9]{16}\\b');
  const [testString, setTestString] = useState('const authHeader = "Bearer TOKEN-AB12CD34EF56GH78";');
  const [testResult, setTestResult] = useState<{ matched: boolean; matches: string[]; error?: string }>({
    matched: true,
    matches: ['TOKEN-AB12CD34EF56GH78']
  });

  // Run live test
  const handleTestRegex = (p: string, str: string) => {
    setTestPattern(p);
    setTestString(str);
    try {
      const regex = new RegExp(p, 'g');
      const matches = str.match(regex) || [];
      setTestResult({
        matched: matches.length > 0,
        matches: Array.from(matches)
      });
    } catch (err: any) {
      setTestResult({
        matched: false,
        matches: [],
        error: err.message
      });
    }
  };

  // Connect builder to sandbox
  const handleSendToSandbox = (pat: string, testStr: string) => {
    setSandboxPattern(pat);
    if (testStr) setSandboxText(testStr);
    setIsSandboxOpen(true);
    setTimeout(() => {
      const sandboxElem = document.getElementById('regex-sandbox-section');
      if (sandboxElem) {
        sandboxElem.scrollIntoView({ behavior: 'smooth' });
      }
    }, 50);
  };

  // Connect builder to playground
  const handleSendToPlayground = (pat: string, testStr: string) => {
    handleTestRegex(pat, testStr);
    handleSendToSandbox(pat, testStr);
  };

  // Open modal pre-filled with builder values for deep manual editing
  const handleOpenAdvancedModal = (initialValues: Partial<RegexRule>) => {
    if (initialValues.name) setName(initialValues.name);
    if (initialValues.pattern) setPattern(initialValues.pattern);
    if (initialValues.flags) setFlags(initialValues.flags);
    if (initialValues.category) setCategory(initialValues.category);
    if (initialValues.severity) setSeverity(initialValues.severity);
    if (initialValues.description) setDescription(initialValues.description);
    if (initialValues.remediation) setRemediation(initialValues.remediation);
    if (initialValues.minEntropy !== undefined) setMinEntropy(initialValues.minEntropy);
    if (initialValues.exampleMatch) setExampleMatch(initialValues.exampleMatch);

    setModalTab('manual');
    setShowAddModal(true);
  };

  const handleSaveRule = () => {
    if (!name.trim() || !pattern.trim()) return;

    try {
      new RegExp(pattern, flags);
    } catch (err) {
      alert('Expressão Regular inválida. Por favor verifique a sintaxe do regex.');
      return;
    }

    const newRule: RegexRule = {
      id: `custom-${Date.now()}`,
      name: name.trim(),
      pattern: pattern.trim(),
      flags,
      category,
      severity,
      description: description.trim() || 'Regra personalizada definida pelo usuário.',
      remediation: remediation.trim() || 'Revogue a credencial e configure via variáveis de ambiente.',
      minEntropy: minEntropy > 0 ? minEntropy : undefined,
      enabled: true,
      isCustom: true,
      exampleMatch: exampleMatch.trim() || undefined,
      tags: ['custom', category.toLowerCase()]
    };

    onAddRule(newRule);
    setShowAddModal(false);

    // Reset form
    setName('');
    setPattern('');
    setDescription('');
    setRemediation('');
  };

  const handleFileImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const imported = JSON.parse(event.target?.result as string);
        if (Array.isArray(imported)) {
          onImportRules(imported);
        }
      } catch (err) {
        alert('Erro ao carregar arquivo de regras. Formato JSON inválido.');
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Controls */}
      <div className="bg-[#0A0A0A] p-6 sm:p-8 border border-[#222] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // REGEX PATTERN SPECIFICATIONS
            </span>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-[#141414] text-white border border-[#333]">
              {rules.length} ACTIVE RULES
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white uppercase mt-1">
            Custom Regex Rules Engine
          </h1>
          <p className="text-xs font-mono text-[#888] mt-1.5 max-w-2xl leading-relaxed">
            Adicione padrões regex sob medida para identificar segredos proprietários da sua empresa, formatos de chaves internas, endpoints específicos ou tokens confidenciais.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            id="btn-toggle-regex-sandbox"
            onClick={() => setIsSandboxOpen(!isSandboxOpen)}
            className={`inline-flex items-center gap-2 px-3.5 py-3 text-[10px] font-black uppercase tracking-[0.2em] border transition-colors cursor-pointer ${
              isSandboxOpen 
                ? 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/50 shadow-[0_0_12px_rgba(0,255,65,0.15)]' 
                : 'bg-[#111] text-zinc-300 border-[#333] hover:border-white hover:text-white'
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Regex Sandbox</span>
            {isSandboxOpen ? <ChevronUp className="w-3 h-3 text-[#00FF41]" /> : <ChevronDown className="w-3 h-3" />}
          </button>

          <button
            type="button"
            id="btn-toggle-visual-builder"
            onClick={() => setIsBuilderOpen(!isBuilderOpen)}
            className={`inline-flex items-center gap-2 px-3.5 py-3 text-[10px] font-black uppercase tracking-[0.2em] border transition-colors cursor-pointer ${
              isBuilderOpen 
                ? 'bg-[#FF3E00]/10 text-[#FF3E00] border-[#FF3E00]/50 shadow-[0_0_12px_rgba(255,62,0,0.15)]' 
                : 'bg-[#111] text-zinc-300 border-[#333] hover:border-white hover:text-white'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Construtor Visual</span>
            {isBuilderOpen ? <ChevronUp className="w-3 h-3 text-[#FF3E00]" /> : <ChevronDown className="w-3 h-3" />}
          </button>

          <label className="inline-flex items-center gap-2 px-3.5 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] cursor-pointer transition-colors">
            <Upload className="w-3.5 h-3.5" />
            <span>Importar</span>
            <input type="file" accept=".json" onChange={handleFileImport} className="hidden" />
          </label>

          <button
            onClick={onExportRules}
            className="inline-flex items-center gap-2 px-3.5 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-white bg-[#111] hover:bg-white hover:text-black border border-[#333] transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Exportar</span>
          </button>

          <button
            onClick={() => {
              setModalTab('sandbox');
              setShowAddModal(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-black bg-white hover:bg-[#FF3E00] hover:text-white transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Nova Regra</span>
          </button>
        </div>
      </div>

      {/* Primary Feature: Interactive Regex Sandbox with Live Highlighting & Group Visualizer */}
      {isSandboxOpen && (
        <div id="regex-sandbox-section" className="space-y-2">
          <RegexSandbox
            initialPattern={sandboxPattern}
            initialFlags={sandboxFlags}
            initialText={sandboxText}
            activeRules={rules}
            onSaveRule={(newRule) => {
              onAddRule(newRule);
            }}
            onOpenManualModal={handleOpenAdvancedModal}
          />
        </div>
      )}

      {/* Visual Regex Rule Builder (Guided Archetype Engine) */}
      {isBuilderOpen && (
        <div id="visual-regex-rule-builder-section" className="space-y-2">
          <RegexRuleBuilder
            onAddRule={onAddRule}
            onSendToPlayground={handleSendToSandbox}
            onOpenAdvancedModal={handleOpenAdvancedModal}
          />
        </div>
      )}

      {/* Interactive Live Regex Playground */}
      <div id="live-regex-playground" className="bg-[#080808] border border-[#222] p-6 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#222]">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-[#FF3E00]" />
            <h2 className="text-[11px] font-black tracking-[0.2em] uppercase text-white">Live Regex Validation Laboratory</h2>
          </div>
          <span className="text-[10px] font-mono text-[#666] uppercase">SYNTAX_VERIFIER_V4</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Expressão Regular (Pattern)</label>
            <input
              type="text"
              value={testPattern}
              onChange={(e) => handleTestRegex(e.target.value, testString)}
              placeholder="Ex: \\bSECRET-[0-9]{8}\\b"
              className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-[#00FF41] focus:outline-none focus:border-[#FF3E00]"
            />
          </div>

          <div>
            <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Texto de Teste / Linha de Código</label>
            <input
              type="text"
              value={testString}
              onChange={(e) => handleTestRegex(testPattern, e.target.value)}
              placeholder="Cole uma linha de código para testar a captura..."
              className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-zinc-200 focus:outline-none focus:border-[#FF3E00]"
            />
          </div>
        </div>

        {/* Live match output */}
        <div className="p-3.5 bg-[#000] border border-[#1A1A1A] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[#666]">MATCH STATUS:</span>
            {testResult.error ? (
              <span className="text-[#FF3E00] font-bold">SYNTAX_ERROR: {testResult.error}</span>
            ) : testResult.matched ? (
              <span className="text-[#00FF41] font-bold flex items-center gap-1.5">
                <Check className="w-3.5 h-3.5" />
                {testResult.matches.length} MATCH(ES) DETECTED:
              </span>
            ) : (
              <span className="text-[#666]">NO_MATCH_FOUND</span>
            )}

            {testResult.matches.map((m, idx) => (
              <code key={idx} className="bg-[#141414] text-[#00FF41] px-2 py-0.5 border border-[#222] font-mono text-[11px]">
                {m}
              </code>
            ))}
          </div>

          <button
            onClick={() => {
              setPattern(testPattern);
              setName('Regra Testada no Playground');
              setShowAddModal(true);
            }}
            className="text-[10px] font-black uppercase tracking-[0.15em] text-[#FF3E00] hover:underline shrink-0"
          >
            Converter em Regra Ativa &rarr;
          </button>
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-[#0A0A0A] border border-[#222] overflow-hidden">
        <div className="px-5 py-3.5 bg-[#080808] border-b border-[#222] flex items-center justify-between">
          <h2 className="text-[10px] font-black uppercase tracking-[0.2em] text-[#666]">
            Static Analysis Rules Repository ({rules.length})
          </h2>
          <span className="text-[10px] font-mono text-[#555] uppercase">BUILT-IN + CUSTOM SPECIFICATIONS</span>
        </div>

        <div className="divide-y divide-[#141414]">
          {rules.map((rule) => {
            const isCustom = rule.isCustom;
            return (
              <div key={rule.id} className="p-5 hover:bg-[#111] transition-colors flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                <div className="space-y-2 flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <button
                      onClick={() => onToggleRule(rule.id)}
                      className={`w-4 h-4 rounded-none flex items-center justify-center border transition-colors ${
                        rule.enabled 
                          ? 'bg-[#FF3E00] border-[#FF3E00] text-white' 
                          : 'border-[#333] bg-[#050505]'
                      }`}
                    >
                      {rule.enabled && <Check className="w-3 h-3 stroke-[3]" />}
                    </button>

                    <span className="font-bold text-xs text-white">{rule.name}</span>

                    {isCustom && (
                      <span className="px-1.5 py-0.5 text-[9px] font-mono font-bold bg-[#141414] text-[#AAA] border border-[#333] uppercase">
                        CUSTOM REGEX
                      </span>
                    )}

                    <span className={`px-2 py-0.5 text-[9px] font-mono font-black uppercase tracking-wider ${
                      rule.severity === 'CRITICAL' ? 'bg-[#FF3E00] text-white' :
                      rule.severity === 'HIGH' ? 'bg-[#FF7A00] text-black font-bold' :
                      rule.severity === 'MEDIUM' ? 'bg-amber-500 text-black font-bold' :
                      'bg-[#3366FF] text-white'
                    }`}>
                      {rule.severity}
                    </span>

                    <span className="text-[10px] text-[#666] font-mono uppercase">[{rule.category}]</span>
                  </div>

                  <p className="text-xs text-[#888] font-mono">{rule.description}</p>

                  <div className="flex items-center gap-2 pt-1 font-mono text-[11px] text-[#AAA] overflow-x-auto">
                    <span className="text-[#555]">REGEX:</span>
                    <code className="bg-[#000] px-2 py-0.5 text-[#00FF41] border border-[#1A1A1A] break-all">
                      /{rule.pattern}/{rule.flags || 'g'}
                    </code>
                    {rule.minEntropy && (
                      <span className="text-[#666] text-[10px]">
                        (H_MIN: {rule.minEntropy})
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleTestRegex(rule.pattern, rule.exampleMatch || 'exemplo de teste com segredo')}
                    className="px-3 py-1.5 text-[10px] font-black uppercase tracking-[0.15em] border border-[#333] hover:border-white text-white hover:bg-white hover:text-black transition-colors"
                  >
                    Testar
                  </button>

                  {isCustom && (
                    <button
                      onClick={() => onDeleteRule(rule.id)}
                      className="p-1.5 text-[#666] hover:text-[#FF3E00] border border-transparent hover:border-[#222] transition-colors"
                      title="Excluir regra customizada"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Add Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className={`bg-[#0A0A0A] w-full border border-[#333] space-y-4 max-h-[92vh] overflow-y-auto ${modalTab !== 'manual' ? 'max-w-4xl p-5 sm:p-7' : 'max-w-xl p-6'}`}>
            <div className="flex items-center justify-between pb-3 border-b border-[#222]">
              <div className="flex items-center gap-3">
                <h3 className="text-xs font-black uppercase tracking-[0.2em] text-white flex items-center gap-2">
                  <Plus className="w-4 h-4 text-[#FF3E00]" />
                  <span>Nova Regra de Detecção Regex</span>
                </h3>
                <div className="flex items-center border border-[#333] bg-[#050505] p-0.5 text-[9px] font-mono">
                  <button
                    type="button"
                    onClick={() => setModalTab('sandbox')}
                    className={`px-2.5 py-1 uppercase font-bold transition-colors cursor-pointer ${
                      modalTab === 'sandbox' 
                        ? 'bg-[#00FF41] text-black' 
                        : 'text-[#888] hover:text-white'
                    }`}
                  >
                    Sandbox Interativo
                  </button>
                  <button
                    type="button"
                    onClick={() => setModalTab('visual')}
                    className={`px-2.5 py-1 uppercase font-bold transition-colors cursor-pointer ${
                      modalTab === 'visual' 
                        ? 'bg-[#FF3E00] text-white' 
                        : 'text-[#888] hover:text-white'
                    }`}
                  >
                    Construtor Visual
                  </button>
                  <button
                    type="button"
                    onClick={() => setModalTab('manual')}
                    className={`px-2.5 py-1 uppercase font-bold transition-colors cursor-pointer ${
                      modalTab === 'manual' 
                        ? 'bg-white text-black' 
                        : 'text-[#888] hover:text-white'
                    }`}
                  >
                    Manual (Avançado)
                  </button>
                </div>
              </div>
              <button 
                onClick={() => setShowAddModal(false)} 
                className="text-[#666] hover:text-white text-xl font-bold w-7 h-7 flex items-center justify-center cursor-pointer"
              >
                &times;
              </button>
            </div>

            {modalTab === 'sandbox' ? (
              <div className="space-y-4">
                <RegexSandbox
                  initialPattern={pattern || sandboxPattern}
                  initialFlags={flags || sandboxFlags}
                  onSaveRule={(r) => {
                    onAddRule(r);
                    setShowAddModal(false);
                  }}
                  onOpenManualModal={(vals) => {
                    handleOpenAdvancedModal(vals);
                  }}
                />
              </div>
            ) : modalTab === 'visual' ? (
              <div className="space-y-4">
                <RegexRuleBuilder
                  onAddRule={(r) => {
                    onAddRule(r);
                    setShowAddModal(false);
                  }}
                  onSendToPlayground={(pat, testStr) => {
                    setShowAddModal(false);
                    handleSendToPlayground(pat, testStr);
                  }}
                  onOpenAdvancedModal={(vals) => {
                    handleOpenAdvancedModal(vals);
                  }}
                />
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Nome da Regra *</label>
                    <input
                      type="text"
                      placeholder="Ex: Token de Pagamento Interno"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Categoria</label>
                    <select
                      value={category}
                      onChange={(e) => setCategory(e.target.value as FindingCategory)}
                      className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                    >
                      <option value="CUSTOM_REGEX">Regra Customizada Geral</option>
                      <option value="API_KEY">Chave de API</option>
                      <option value="CLOUD_CREDENTIAL">Credencial de Nuvem</option>
                      <option value="AUTH_TOKEN">Token de Autenticação</option>
                      <option value="DATABASE_URI">URI de Banco de Dados</option>
                      <option value="PASSWORD">Senha Hardcoded</option>
                      <option value="API_PATH">Caminho de Rota de API</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Padrão Regex (Pattern) *</label>
                  <input
                    type="text"
                    placeholder="Ex: \\bCORP-[A-Z0-9]{20,32}\\b"
                    value={pattern}
                    onChange={(e) => setPattern(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-[#00FF41] focus:border-[#FF3E00] focus:outline-none"
                  />
                  <p className="text-[10px] font-mono text-[#666] mt-1">Lembre-se de escapar barras invertidas (ex: \\b para limites de palavra).</p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div>
                    <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Severidade</label>
                    <select
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                      className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                    >
                      <option value="CRITICAL">Crítica</option>
                      <option value="HIGH">Alta</option>
                      <option value="MEDIUM">Média</option>
                      <option value="LOW">Baixa</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Flags</label>
                    <input
                      type="text"
                      value={flags}
                      onChange={(e) => setFlags(e.target.value)}
                      placeholder="g, gi"
                      className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Entropia Mínima</label>
                    <input
                      type="number"
                      step="0.1"
                      min="0"
                      max="8"
                      value={minEntropy}
                      onChange={(e) => setMinEntropy(parseFloat(e.target.value))}
                      className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Descrição do Problema</label>
                  <textarea
                    rows={2}
                    placeholder="Explique o que essa chave confere de acesso e por que não deve ficar exposta..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className="w-full p-2.5 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                  />
                </div>

                <div>
                  <label className="text-[10px] font-black uppercase tracking-wider text-[#888] block mb-1">Instrução de Remediação</label>
                  <textarea
                    rows={2}
                    placeholder="Ex: Rotacione o token no serviço de autenticação e injete via process.env..."
                    value={remediation}
                    onChange={(e) => setRemediation(e.target.value)}
                    className="w-full p-2.5 text-xs bg-[#050505] border border-[#222] text-white font-mono focus:border-[#FF3E00] focus:outline-none"
                  />
                </div>

                <div className="flex justify-end gap-3 pt-3 border-t border-[#222]">
                  <button
                    onClick={() => setShowAddModal(false)}
                    className="px-4 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-[#888] hover:text-white border border-[#222] cursor-pointer"
                  >
                    Cancelar
                  </button>
                  <button
                    onClick={handleSaveRule}
                    disabled={!name.trim() || !pattern.trim()}
                    className="px-5 py-2 text-[10px] font-black uppercase tracking-[0.15em] text-black bg-white hover:bg-[#FF3E00] hover:text-white disabled:opacity-40 transition-colors cursor-pointer"
                  >
                    Salvar Regra
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
