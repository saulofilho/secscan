import React, { useState, useMemo, useEffect } from 'react';
import { 
  KeyRound, 
  Cloud, 
  CreditCard, 
  Database, 
  Lock, 
  Sparkles, 
  Check, 
  Copy, 
  Plus, 
  Play, 
  Sliders, 
  ShieldAlert, 
  FileCode, 
  RefreshCw,
  HelpCircle,
  Hash,
  Layers,
  ArrowRight,
  Info,
  Terminal
} from 'lucide-react';
import { RegexRule, FindingCategory, SeverityLevel } from '../types';

export type SecretArchetypeId = 
  | 'aws-akid'
  | 'aws-secret'
  | 'generic-token'
  | 'github-token'
  | 'stripe-key'
  | 'google-key'
  | 'slack-token'
  | 'jwt-token'
  | 'database-uri'
  | 'private-key'
  | 'corporate-token';

export interface SecretArchetype {
  id: SecretArchetypeId;
  name: string;
  shortName: string;
  category: FindingCategory;
  defaultSeverity: SeverityLevel;
  severityRationale: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  defaultPrefix: string;
  defaultPrefixes?: string[];
  charset: 'ALPHANUMERIC' | 'UPPER_ALPHANUMERIC' | 'HEX' | 'BASE64URL' | 'BASE64' | 'CUSTOM';
  customCharset?: string;
  minLength: number;
  maxLength: number;
  isExactLength: boolean;
  wordBoundary: boolean;
  requiresAssignment: boolean;
  caseInsensitive: boolean;
  recommendedEntropy: number;
  sampleSecret: string;
  remediation: string;
  tags: string[];
}

export const SECRET_ARCHETYPES: SecretArchetype[] = [
  {
    id: 'aws-akid',
    name: 'AWS Access Key ID',
    shortName: 'AWS Key',
    category: 'CLOUD_CREDENTIAL',
    defaultSeverity: 'CRITICAL',
    severityRationale: 'Acesso direto a contas de nuvem AWS com potencial para destruição de infraestrutura, exfiltração de dados e custos massivos.',
    icon: Cloud,
    description: 'Chaves de API públicas de identificação AWS IAM (AKIA, ASIA, ACCA, AIDA).',
    defaultPrefix: 'AKIA',
    defaultPrefixes: ['AKIA', 'ASIA', 'ACCA', 'AIDA', 'AROA'],
    charset: 'UPPER_ALPHANUMERIC',
    minLength: 16,
    maxLength: 16,
    isExactLength: true,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 3.5,
    sampleSecret: 'DEMO_AWS_AKID_EXAMPLE_KEY_01',
    remediation: 'Rotacione a chave no AWS IAM Console e utilize IAM Roles (STS) ou AWS Secrets Manager.',
    tags: ['aws', 'cloud', 'iam', 's3']
  },
  {
    id: 'aws-secret',
    name: 'AWS Secret Access Key',
    shortName: 'AWS Secret',
    category: 'CLOUD_CREDENTIAL',
    defaultSeverity: 'CRITICAL',
    severityRationale: 'Chave secreta privada pareada ao Key ID da AWS. Permite assinatura criptográfica de requisições autenticadas.',
    icon: Cloud,
    description: 'Segredo de 40 caracteres base64 pareado ao Access Key ID da AWS.',
    defaultPrefix: '',
    charset: 'BASE64',
    minLength: 40,
    maxLength: 40,
    isExactLength: true,
    wordBoundary: false,
    requiresAssignment: true,
    caseInsensitive: true,
    recommendedEntropy: 4.2,
    sampleSecret: 'aws_secret_access_key="DEMO_AWS_SECRET_KEY_SAMPLE_TEST_KEY_40"',
    remediation: 'Invalide a chave de acesso imediatamente no console da AWS e expurgue do histórico git.',
    tags: ['aws', 'secrets', 'critical']
  },
  {
    id: 'generic-token',
    name: 'Generic API Token / Secret',
    shortName: 'Generic Token',
    category: 'API_KEY',
    defaultSeverity: 'HIGH',
    severityRationale: 'Chaves e tokens de serviços de terceiros sem formato proprietário estrito, mas com alta entropia informacional.',
    icon: KeyRound,
    description: 'Padrão flexível para tokens genéricos de autenticação (Bearer, API keys, hashes).',
    defaultPrefix: 'token_',
    defaultPrefixes: ['token_', 'api_key_', 'secret_', 'key_'],
    charset: 'BASE64URL',
    minLength: 24,
    maxLength: 64,
    isExactLength: false,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 3.6,
    sampleSecret: 'token_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
    remediation: 'Extraia o token para variável de ambiente (.env) e carregue em tempo de execução.',
    tags: ['generic', 'api-key', 'auth']
  },
  {
    id: 'github-token',
    name: 'GitHub Personal Access Token',
    shortName: 'GitHub PAT',
    category: 'AUTH_TOKEN',
    defaultSeverity: 'CRITICAL',
    severityRationale: 'Acesso a repositórios de código-fonte, branches protegidas, segredos de GitHub Actions e releases.',
    icon: ShieldAlert,
    description: 'Tokens pessoais de acesso clássicos (ghp_) e fine-grained (github_pat_).',
    defaultPrefix: 'ghp_',
    defaultPrefixes: ['ghp_', 'gho_', 'github_pat_'],
    charset: 'ALPHANUMERIC',
    minLength: 36,
    maxLength: 36,
    isExactLength: true,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 4.1,
    sampleSecret: 'DEMO_GITHUB_PAT_TOKEN_SAMPLE_FOR_TESTS',
    remediation: 'Revogue imediatamente em GitHub > Settings > Developer Settings e armazene como GitHub Secret.',
    tags: ['github', 'vcs', 'git', 'pat']
  },
  {
    id: 'stripe-key',
    name: 'Stripe Secret / Restricted Key',
    shortName: 'Stripe Key',
    category: 'API_KEY',
    defaultSeverity: 'CRITICAL',
    severityRationale: 'Permite operações financeiras, criação de cobranças, transferências e acesso a dados confidenciais de cartões.',
    icon: CreditCard,
    description: 'Chaves secretas ou restritas de produção e teste da API Stripe.',
    defaultPrefix: 'sk_live_',
    defaultPrefixes: ['sk_live_', 'rk_live_', 'sk_test_'],
    charset: 'ALPHANUMERIC',
    minLength: 24,
    maxLength: 34,
    isExactLength: false,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 4.0,
    sampleSecret: 'DEMO_STRIPE_SECRET_KEY_FOR_TESTS',
    remediation: 'Revogue a chave imediatamente no Dashboard do Stripe. Nunca exponha chaves secretas no frontend.',
    tags: ['stripe', 'payments', 'pci-dss']
  },
  {
    id: 'google-key',
    name: 'Google Cloud / Gemini API Key',
    shortName: 'Google Key',
    category: 'API_KEY',
    defaultSeverity: 'HIGH',
    severityRationale: 'Consumo de cotas pagas de APIs Google Cloud, Gemini LLM, Maps, Firebase ou Vertex AI.',
    icon: Sparkles,
    description: 'Chaves de API do ecossistema Google Cloud e Gemini com prefixo AIza.',
    defaultPrefix: 'AIza',
    charset: 'BASE64URL',
    minLength: 35,
    maxLength: 35,
    isExactLength: true,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 4.0,
    sampleSecret: 'DEMO_GOOGLE_API_KEY_SAMPLE_TEST_99',
    remediation: 'Restrinja a chave por HTTP referrers no GCP Console ou utilize rotas server-side protegidas.',
    tags: ['google', 'gcp', 'gemini', 'api']
  },
  {
    id: 'database-uri',
    name: 'Database Connection URI with Password',
    shortName: 'Database URI',
    category: 'DATABASE_URI',
    defaultSeverity: 'CRITICAL',
    severityRationale: 'Exposição de credenciais root/admin com acesso direto ao banco de dados relacional ou NoSQL.',
    icon: Database,
    description: 'URIs de conexão para PostgreSQL, MySQL, MongoDB, Redis com usuário e senha em texto claro.',
    defaultPrefix: 'postgres://',
    defaultPrefixes: ['postgres://', 'mongodb://', 'mysql://', 'redis://'],
    charset: 'CUSTOM',
    customCharset: 'URI_PROTOCOL',
    minLength: 20,
    maxLength: 120,
    isExactLength: false,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: true,
    recommendedEntropy: 3.5,
    sampleSecret: 'postgres://app_user:REDACTED_PASSWORD@db.internal.corp:5432/finance_db',
    remediation: 'Configure a string de conexão em DATABASE_URL no .env e use secret stores com rotação automática.',
    tags: ['database', 'postgres', 'mongo', 'mysql']
  },
  {
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    shortName: 'JWT Token',
    category: 'AUTH_TOKEN',
    defaultSeverity: 'MEDIUM',
    severityRationale: 'Tokens de sessão embutidos podem permitir impersonação de usuários ou expirar em prazo curto.',
    icon: Lock,
    description: 'Tokens com cabeçalho eyJ... codificados em base64url estruturados em 3 partes.',
    defaultPrefix: 'eyJ',
    charset: 'BASE64URL',
    minLength: 40,
    maxLength: 300,
    isExactLength: false,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 4.2,
    sampleSecret: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vX3VzZXIifQ.DEMO_SIGNATURE_ONLY',
    remediation: 'Substitua JWTs fixos por endpoints de login dinâmicos e armazene tokens efêmeros em cookies HttpOnly.',
    tags: ['jwt', 'oauth', 'session']
  },
  {
    id: 'private-key',
    name: 'RSA / OpenSSH Private Key Block',
    shortName: 'Private Key',
    category: 'PRIVATE_KEY',
    defaultSeverity: 'CRITICAL',
    severityRationale: 'Chaves assimétricas privadas permitem forjar assinaturas criptográficas ou conectar via SSH como root.',
    icon: FileCode,
    description: 'Blocos delimitadores de certificados e chaves privadas PEM / OpenSSH.',
    defaultPrefix: '-----BEGIN',
    charset: 'CUSTOM',
    minLength: 64,
    maxLength: 4096,
    isExactLength: false,
    wordBoundary: false,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 4.5,
    sampleSecret: '-----' + 'BEGIN [RSA] PRIVATE KEY' + '-----\n[CONTEUDO_CHAVE_PRIVADA_REMOVIDO]\n-----' + 'END [RSA] PRIVATE KEY' + '-----',
    remediation: 'Expurgue a chave privada do repositório imediatamente e configure no SSH Agent ou AWS KMS.',
    tags: ['crypto', 'ssh', 'rsa', 'pem']
  },
  {
    id: 'corporate-token',
    name: 'Custom Corporate / Internal Token',
    shortName: 'Corporate Token',
    category: 'CUSTOM_REGEX',
    defaultSeverity: 'HIGH',
    severityRationale: 'Padrão customizado para credenciais proprietárias da sua empresa ou serviços internos.',
    icon: Sliders,
    description: 'Defina o prefixo da sua organização e gere o regex automaticamente com regras estritas.',
    defaultPrefix: 'CORP_KEY_',
    charset: 'UPPER_ALPHANUMERIC',
    minLength: 24,
    maxLength: 32,
    isExactLength: false,
    wordBoundary: true,
    requiresAssignment: false,
    caseInsensitive: false,
    recommendedEntropy: 3.7,
    sampleSecret: 'CORP_KEY_A9B8C7D6E5F4G3H2J1K0L9M8',
    remediation: 'Injete via variáveis de ambiente da empresa ou HashiCorp Vault.',
    tags: ['corporate', 'internal', 'custom']
  }
];

interface RegexRuleBuilderProps {
  onAddRule: (rule: RegexRule) => void;
  onSendToPlayground?: (pattern: string, testString: string) => void;
  onOpenAdvancedModal?: (initialValues: Partial<RegexRule>) => void;
}

export const RegexRuleBuilder: React.FC<RegexRuleBuilderProps> = ({
  onAddRule,
  onSendToPlayground,
  onOpenAdvancedModal
}) => {
  // Currently selected archetype
  const [selectedArchetypeId, setSelectedArchetypeId] = useState<SecretArchetypeId>('aws-akid');

  // Customization fields initialized from archetype
  const [ruleName, setRuleName] = useState('AWS Access Key ID');
  const [prefix, setPrefix] = useState('AKIA');
  const [selectedPrefixes, setSelectedPrefixes] = useState<string[]>(['AKIA', 'ASIA', 'ACCA', 'AIDA', 'AROA']);
  const [charset, setCharset] = useState<'ALPHANUMERIC' | 'UPPER_ALPHANUMERIC' | 'HEX' | 'BASE64URL' | 'BASE64' | 'CUSTOM'>('UPPER_ALPHANUMERIC');
  const [customCharsetInput, setCustomCharsetInput] = useState('[A-Z0-9]');
  const [minLength, setMinLength] = useState(16);
  const [maxLength, setMaxLength] = useState(16);
  const [isExactLength, setIsExactLength] = useState(true);
  const [wordBoundary, setWordBoundary] = useState(true);
  const [requireAssignment, setRequireAssignment] = useState(false);
  const [assignmentVarName, setAssignmentVarName] = useState('api_key');
  const [caseInsensitive, setCaseInsensitive] = useState(false);
  const [minEntropy, setMinEntropy] = useState(3.5);

  // Overrides for severity & category
  const [severity, setSeverity] = useState<SeverityLevel>('CRITICAL');
  const [category, setCategory] = useState<FindingCategory>('CLOUD_CREDENTIAL');
  const [customDescription, setCustomDescription] = useState('');
  const [customRemediation, setCustomRemediation] = useState('');

  // Live inline testing state
  const [liveTestInput, setLiveTestInput] = useState(
    () => `const key = "DEMO_AWS_AKID_EXAMPLE_KEY_01";`
  );
  const [copiedRegex, setCopiedRegex] = useState(false);
  const [ruleSavedToast, setRuleSavedToast] = useState(false);

  // Load archetype preset
  const handleSelectArchetype = (archetypeId: SecretArchetypeId) => {
    setSelectedArchetypeId(archetypeId);
    const arch = SECRET_ARCHETYPES.find(a => a.id === archetypeId);
    if (!arch) return;

    setRuleName(arch.name);
    setPrefix(arch.defaultPrefix);
    setSelectedPrefixes(arch.defaultPrefixes || (arch.defaultPrefix ? [arch.defaultPrefix] : []));
    setCharset(arch.charset);
    setMinLength(arch.minLength);
    setMaxLength(arch.maxLength);
    setIsExactLength(arch.isExactLength);
    setWordBoundary(arch.wordBoundary);
    setRequireAssignment(arch.requiresAssignment);
    setCaseInsensitive(arch.caseInsensitive);
    setMinEntropy(arch.recommendedEntropy);
    setSeverity(arch.defaultSeverity);
    setCategory(arch.category);
    setCustomDescription(arch.description);
    setCustomRemediation(arch.remediation);
    setLiveTestInput(`const secret = "${arch.sampleSecret}";`);
  };

  // Helper to determine regex character set fragment
  const charsetFragment = useMemo(() => {
    switch (charset) {
      case 'UPPER_ALPHANUMERIC':
        return '[A-Z0-9]';
      case 'ALPHANUMERIC':
        return '[0-9a-zA-Z]';
      case 'HEX':
        return '[0-9a-fA-F]';
      case 'BASE64URL':
        return '[0-9a-zA-Z_\\-]';
      case 'BASE64':
        return '[A-Za-z0-9/+=]';
      case 'CUSTOM':
      default:
        return customCharsetInput.trim() || '[A-Za-z0-9]';
    }
  }, [charset, customCharsetInput]);

  // Dynamically generate regex pattern based on archetype and user parameters
  const generatedPattern = useMemo(() => {
    if (selectedArchetypeId === 'database-uri') {
      return '(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis):\\/\\/[^\\s:"\']+:[^\\s:"\']+@[^\\s:"\']+';
    }

    if (selectedArchetypeId === 'private-key') {
      return '-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----[\\s\\S]*?-----END (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----';
    }

    if (selectedArchetypeId === 'jwt-token') {
      return '\\beyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*\\b';
    }

    // Prefix group
    let prefixPart = '';
    if (selectedPrefixes.length > 1) {
      // Escape special characters in prefixes
      const escaped = selectedPrefixes.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
      prefixPart = `(?:${escaped})`;
    } else if (prefix.trim()) {
      prefixPart = prefix.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // Length quantifier
    let lengthPart = '';
    if (isExactLength || minLength === maxLength) {
      lengthPart = `{${minLength}}`;
    } else {
      lengthPart = `{${minLength},${maxLength}}`;
    }

    let coreToken = `${prefixPart}${charsetFragment}${lengthPart}`;

    if (requireAssignment) {
      const varName = assignmentVarName.trim() || 'token|api_key|secret';
      coreToken = `(?:${varName})\\s*[:=]\\s*['"]${coreToken}['"]`;
    } else if (wordBoundary) {
      coreToken = `\\b${coreToken}\\b`;
    }

    return coreToken;
  }, [
    selectedArchetypeId,
    selectedPrefixes,
    prefix,
    charsetFragment,
    isExactLength,
    minLength,
    maxLength,
    requireAssignment,
    assignmentVarName,
    wordBoundary
  ]);

  // Flags
  const generatedFlags = useMemo(() => {
    let f = 'g';
    if (caseInsensitive || selectedArchetypeId === 'database-uri') f += 'i';
    return f;
  }, [caseInsensitive, selectedArchetypeId]);

  // Auto calculate severity rationale & badge
  const currentArchetype = useMemo(() => {
    return SECRET_ARCHETYPES.find(a => a.id === selectedArchetypeId) || SECRET_ARCHETYPES[0];
  }, [selectedArchetypeId]);

  // Dynamic live regex tester output
  const liveTestResult = useMemo(() => {
    try {
      const re = new RegExp(generatedPattern, generatedFlags);
      const matches = liveTestInput.match(re);
      return {
        validRegex: true,
        matched: Boolean(matches && matches.length > 0),
        matches: matches ? Array.from(matches) : [],
        error: null
      };
    } catch (err: any) {
      return {
        validRegex: false,
        matched: false,
        matches: [],
        error: err.message
      };
    }
  }, [generatedPattern, generatedFlags, liveTestInput]);

  // Generated sample matching secret
  const generatedSample = useMemo(() => {
    return currentArchetype.sampleSecret;
  }, [currentArchetype]);

  const handleCopyPattern = () => {
    navigator.clipboard.writeText(`/${generatedPattern}/${generatedFlags}`);
    setCopiedRegex(true);
    setTimeout(() => setCopiedRegex(false), 2000);
  };

  const handleCreateRule = () => {
    if (!ruleName.trim() || !generatedPattern.trim()) return;

    try {
      new RegExp(generatedPattern, generatedFlags);
    } catch (err) {
      alert('A expressão regular gerada contém erro sintático.');
      return;
    }

    const newRule: RegexRule = {
      id: `builder-${Date.now()}`,
      name: ruleName.trim(),
      pattern: generatedPattern.trim(),
      flags: generatedFlags,
      category,
      severity,
      description: customDescription.trim() || currentArchetype.description,
      remediation: customRemediation.trim() || currentArchetype.remediation,
      minEntropy: minEntropy > 0 ? minEntropy : undefined,
      enabled: true,
      isCustom: true,
      exampleMatch: generatedSample,
      tags: ['builder', currentArchetype.id, category.toLowerCase()]
    };

    onAddRule(newRule);
    setRuleSavedToast(true);
    setTimeout(() => setRuleSavedToast(false), 3000);
  };

  const handleSendToLab = () => {
    if (onSendToPlayground) {
      onSendToPlayground(generatedPattern, liveTestInput || generatedSample);
    }
  };

  const handleOpenAdvanced = () => {
    if (onOpenAdvancedModal) {
      onOpenAdvancedModal({
        name: ruleName,
        pattern: generatedPattern,
        flags: generatedFlags,
        category,
        severity,
        description: customDescription || currentArchetype.description,
        remediation: customRemediation || currentArchetype.remediation,
        minEntropy,
        exampleMatch: generatedSample
      });
    }
  };

  // Toggle prefix helper
  const handleTogglePrefix = (pref: string) => {
    if (selectedPrefixes.includes(pref)) {
      if (selectedPrefixes.length > 1) {
        setSelectedPrefixes(selectedPrefixes.filter(p => p !== pref));
      }
    } else {
      setSelectedPrefixes([...selectedPrefixes, pref]);
    }
  };

  return (
    <div className="bg-[#0A0A0A] border border-[#222] p-5 sm:p-7 space-y-6">
      {/* Builder Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-none bg-[#FF3E00] flex items-center justify-center text-white font-black text-xs">
              <Sparkles className="w-3.5 h-3.5" />
            </div>
            <h2 className="text-sm sm:text-base font-black uppercase tracking-[0.2em] text-white">
              Visual Regex Rule Builder
            </h2>
            <span className="px-2 py-0.5 text-[9px] font-mono font-bold bg-[#00FF41]/10 text-[#00FF41] border border-[#00FF41]/30 uppercase">
              Guided Archetype Engine
            </span>
          </div>
          <p className="text-xs font-mono text-[#888] max-w-3xl">
            Selecione um arquétipo de credencial comum (AWS, Tokens de API, GitHub, Stripe, etc.). O gerador ajusta dinamicamente a expressão regular, a severidade recomendada e as referências de remediação.
          </p>
        </div>

        {ruleSavedToast && (
          <div className="animate-in fade-in zoom-in-95 duration-200 px-3 py-1.5 bg-[#00FF41] text-black font-mono font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(0,255,65,0.4)]">
            <Check className="w-4 h-4" />
            <span>REGRA ATIVADA COM SUCESSO!</span>
          </div>
        )}
      </div>

      {/* Step 1: Secret Archetypes Grid */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <label className="text-[10px] font-black uppercase tracking-[0.2em] text-[#888] flex items-center gap-2">
            <span className="w-4 h-4 bg-[#141414] border border-[#333] text-white flex items-center justify-center text-[10px] font-bold">1</span>
            <span>Selecione o Tipo de Segredo (Secret Archetype)</span>
          </label>
          <span className="text-[10px] font-mono text-[#555]">
            {SECRET_ARCHETYPES.length} TEMPLATES DISPONÍVEIS
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-2.5">
          {SECRET_ARCHETYPES.map((arch) => {
            const Icon = arch.icon;
            const isSelected = arch.id === selectedArchetypeId;
            return (
              <button
                key={arch.id}
                type="button"
                id={`archetype-btn-${arch.id}`}
                onClick={() => handleSelectArchetype(arch.id)}
                className={`p-3 text-left transition-all relative border flex flex-col justify-between min-h-[95px] cursor-pointer group ${
                  isSelected
                    ? 'bg-[#141414] border-[#FF3E00] shadow-[0_0_12px_rgba(255,62,0,0.18)]'
                    : 'bg-[#080808] border-[#1F1F1F] hover:border-[#444] hover:bg-[#0D0D0D]'
                }`}
              >
                <div className="flex items-start justify-between w-full">
                  <Icon className={`w-4 h-4 ${isSelected ? 'text-[#FF3E00]' : 'text-[#888] group-hover:text-white'}`} />
                  <span className={`px-1.5 py-0.2 text-[8px] font-mono font-black uppercase tracking-wider ${
                    arch.defaultSeverity === 'CRITICAL' ? 'bg-[#FF3E00]/20 text-[#FF3E00]' :
                    arch.defaultSeverity === 'HIGH' ? 'bg-[#FF7A00]/20 text-[#FF7A00]' :
                    'bg-amber-500/20 text-amber-400'
                  }`}>
                    {arch.defaultSeverity}
                  </span>
                </div>

                <div className="mt-2">
                  <div className={`font-bold text-xs truncate ${isSelected ? 'text-white' : 'text-zinc-300'}`}>
                    {arch.shortName}
                  </div>
                  <div className="text-[9px] font-mono text-[#666] truncate mt-0.5">
                    {arch.defaultPrefix ? `Prefixo: ${arch.defaultPrefix}` : 'Padrão Estruturado'}
                  </div>
                </div>

                {isSelected && (
                  <div className="absolute top-0 right-0 w-2 h-2 bg-[#FF3E00]" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Step 2 & 3: Guided Configuration & Parameters */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-2">
        {/* Left Column: Visual Customizer Controls (7 cols) */}
        <div className="lg:col-span-7 space-y-5">
          <div className="flex items-center justify-between pb-2 border-b border-[#1A1A1A]">
            <label className="text-[10px] font-black uppercase tracking-[0.2em] text-[#888] flex items-center gap-2">
              <span className="w-4 h-4 bg-[#141414] border border-[#333] text-white flex items-center justify-center text-[10px] font-bold">2</span>
              <span>Parâmetros de Detecção & Formato</span>
            </label>
            <span className="text-[10px] font-mono text-[#00FF41]">
              [AUTO-CONFIGURADO PELO ARQUÉTIPO]
            </span>
          </div>

          {/* Rule Name & Category Input */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Nome da Regra
              </label>
              <input
                type="text"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder="Nome da especificação..."
                className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
              />
            </div>

            <div>
              <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                Categoria de Descoberta
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as FindingCategory)}
                className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
              >
                <option value="CLOUD_CREDENTIAL">CLOUD_CREDENTIAL (Nuvem)</option>
                <option value="API_KEY">API_KEY (Chave de API)</option>
                <option value="AUTH_TOKEN">AUTH_TOKEN (Token de Acesso)</option>
                <option value="DATABASE_URI">DATABASE_URI (Banco de Dados)</option>
                <option value="PRIVATE_KEY">PRIVATE_KEY (Chave Privada)</option>
                <option value="PASSWORD">PASSWORD (Senha Hardcoded)</option>
                <option value="CUSTOM_REGEX">CUSTOM_REGEX (Padrão Proprietário)</option>
              </select>
            </div>
          </div>

          {/* Prefix options */}
          {selectedArchetypeId !== 'database-uri' && selectedArchetypeId !== 'private-key' && selectedArchetypeId !== 'jwt-token' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[10px] font-mono uppercase text-[#777] flex items-center gap-1.5">
                  <span>Prefixos Obrigatórios</span>
                  <Info className="w-3 h-3 text-[#555]" />
                </label>
                <span className="text-[10px] font-mono text-[#555]">
                  {selectedPrefixes.length > 1 ? `Multi-prefixo: (?:${selectedPrefixes.join('|')})` : 'Prefixo único'}
                </span>
              </div>

              {currentArchetype.defaultPrefixes && currentArchetype.defaultPrefixes.length > 1 && (
                <div className="flex flex-wrap gap-1.5 mb-2">
                  {currentArchetype.defaultPrefixes.map(pref => {
                    const active = selectedPrefixes.includes(pref);
                    return (
                      <button
                        key={pref}
                        type="button"
                        onClick={() => handleTogglePrefix(pref)}
                        className={`px-2 py-1 text-[10px] font-mono border transition-colors cursor-pointer ${
                          active
                            ? 'bg-[#FF3E00]/20 border-[#FF3E00] text-white font-bold'
                            : 'bg-[#111] border-[#222] text-[#777] hover:border-[#444]'
                        }`}
                      >
                        {active ? '✓ ' : '+ '}{pref}
                      </button>
                    );
                  })}
                </div>
              )}

              <input
                type="text"
                value={prefix}
                onChange={(e) => {
                  setPrefix(e.target.value);
                  setSelectedPrefixes([e.target.value]);
                }}
                placeholder="Ex: AKIA, sk_live_, ghp_, CORP_TOKEN_"
                className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-[#00FF41] focus:outline-none focus:border-[#FF3E00]"
              />
            </div>
          )}

          {/* Charset & Length Controls */}
          {selectedArchetypeId !== 'database-uri' && selectedArchetypeId !== 'private-key' && selectedArchetypeId !== 'jwt-token' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] font-mono uppercase text-[#777] block mb-1">
                  Conjunto de Caracteres (Charset)
                </label>
                <select
                  value={charset}
                  onChange={(e) => setCharset(e.target.value as any)}
                  className="w-full px-3 py-2 text-xs bg-[#050505] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
                >
                  <option value="UPPER_ALPHANUMERIC">Alfanumérico Maiúsculo [A-Z0-9]</option>
                  <option value="ALPHANUMERIC">Alfanumérico Geral [0-9a-zA-Z]</option>
                  <option value="HEX">Hexadecimal [0-9a-fA-F]</option>
                  <option value="BASE64URL">URL-Safe Base64 [0-9a-zA-Z_\-]</option>
                  <option value="BASE64">Base64 Padrão [A-Za-z0-9/+=]</option>
                  <option value="CUSTOM">Regex Personalizado (Charset)</option>
                </select>

                {charset === 'CUSTOM' && (
                  <input
                    type="text"
                    value={customCharsetInput}
                    onChange={(e) => setCustomCharsetInput(e.target.value)}
                    placeholder="Ex: [A-Z0-9_]"
                    className="w-full mt-2 px-3 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-[#00FF41]"
                  />
                )}
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-[10px] font-mono uppercase text-[#777]">
                    Comprimento do Token
                  </label>
                  <label className="text-[9px] font-mono text-[#888] flex items-center gap-1 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={isExactLength}
                      onChange={(e) => {
                        setIsExactLength(e.target.checked);
                        if (e.target.checked) setMaxLength(minLength);
                      }}
                      className="accent-[#FF3E00]"
                    />
                    <span>Exato ({minLength})</span>
                  </label>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex-1">
                    <span className="text-[9px] font-mono text-[#555] block">MÍNIMO</span>
                    <input
                      type="number"
                      min="1"
                      max="512"
                      value={minLength}
                      onChange={(e) => {
                        const val = Math.max(1, parseInt(e.target.value) || 1);
                        setMinLength(val);
                        if (isExactLength || val > maxLength) setMaxLength(val);
                      }}
                      className="w-full px-2.5 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white"
                    />
                  </div>

                  {!isExactLength && (
                    <div className="flex-1">
                      <span className="text-[9px] font-mono text-[#555] block">MÁXIMO</span>
                      <input
                        type="number"
                        min={minLength}
                        max="1024"
                        value={maxLength}
                        onChange={(e) => setMaxLength(Math.max(minLength, parseInt(e.target.value) || minLength))}
                        className="w-full px-2.5 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-white"
                      />
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Context & Boundary Toggles */}
          <div className="p-3.5 bg-[#080808] border border-[#1A1A1A] space-y-2.5">
            <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-[#666] block">
              Restrições de Sintaxe & Limite de Palavra
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                <input
                  type="checkbox"
                  checked={wordBoundary}
                  onChange={(e) => setWordBoundary(e.target.checked)}
                  className="accent-[#FF3E00]"
                />
                <span className="text-[11px]">Limite de Palavra (\b...\b)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white">
                <input
                  type="checkbox"
                  checked={caseInsensitive}
                  onChange={(e) => setCaseInsensitive(e.target.checked)}
                  className="accent-[#FF3E00]"
                />
                <span className="text-[11px]">Case-Insensitive (/i)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-zinc-300 hover:text-white sm:col-span-2">
                <input
                  type="checkbox"
                  checked={requireAssignment}
                  onChange={(e) => setRequireAssignment(e.target.checked)}
                  className="accent-[#FF3E00]"
                />
                <span className="text-[11px]">Exigir Atribuição (ex: api_key = "...")</span>
              </label>
            </div>

            {requireAssignment && (
              <div className="pt-2 border-t border-[#141414]">
                <label className="text-[9px] font-mono uppercase text-[#777] block mb-1">
                  Nomes de Variáveis Aceitos (Regex alternativo)
                </label>
                <input
                  type="text"
                  value={assignmentVarName}
                  onChange={(e) => setAssignmentVarName(e.target.value)}
                  placeholder="token|api_key|secret_key|auth_secret"
                  className="w-full px-2.5 py-1.5 text-xs bg-[#050505] border border-[#222] font-mono text-[#00FF41]"
                />
              </div>
            )}
          </div>

          {/* Entropy Threshold Slider */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-[10px] uppercase text-[#777] flex items-center gap-1.5">
                <span>Limiar de Entropia Mínima de Shannon (H_min)</span>
                <span className="text-[#00FF41] font-bold">{minEntropy} bits/char</span>
              </span>
              <span className="text-[9px] text-[#555]">
                {minEntropy >= 4.0 ? 'Alta Entropia (Filtra mocks)' : minEntropy > 0 ? 'Entropia Moderada' : 'Sem filtro de entropia'}
              </span>
            </div>
            <input
              type="range"
              min="0"
              max="5.5"
              step="0.1"
              value={minEntropy}
              onChange={(e) => setMinEntropy(parseFloat(e.target.value))}
              className="w-full accent-[#00FF41] bg-[#222] h-1.5"
            />
          </div>
        </div>

        {/* Right Column: Auto-Calculated Severity, Live Pattern & Testing (5 cols) */}
        <div className="lg:col-span-5 space-y-4 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[#1A1A1A]">
              <label className="text-[10px] font-black uppercase tracking-[0.2em] text-[#888] flex items-center gap-2">
                <span className="w-4 h-4 bg-[#141414] border border-[#333] text-white flex items-center justify-center text-[10px] font-bold">3</span>
                <span>Severidade & Padrão Gerado</span>
              </label>
              <span className="text-[10px] font-mono text-[#FF3E00]">
                [AI / HEURISTIC RATIONALE]
              </span>
            </div>

            {/* Auto-Calculated Severity Box */}
            <div className="p-4 bg-[#080808] border border-[#222] space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-mono uppercase text-[#777]">Severidade Recomendada:</span>
                <div className="flex items-center gap-1.5">
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as SeverityLevel[]).map((lvl) => {
                    const isCurrent = severity === lvl;
                    return (
                      <button
                        key={lvl}
                        type="button"
                        onClick={() => setSeverity(lvl)}
                        className={`px-2 py-0.5 text-[9px] font-mono font-black uppercase tracking-wider transition-all cursor-pointer ${
                          isCurrent
                            ? lvl === 'CRITICAL' ? 'bg-[#FF3E00] text-white shadow-[0_0_8px_rgba(255,62,0,0.4)]' :
                              lvl === 'HIGH' ? 'bg-[#FF7A00] text-black shadow-[0_0_8px_rgba(255,122,0,0.4)]' :
                              lvl === 'MEDIUM' ? 'bg-amber-500 text-black' :
                              'bg-blue-600 text-white'
                            : 'bg-[#141414] text-[#666] border border-[#222] hover:text-white'
                        }`}
                      >
                        {lvl}
                      </button>
                    );
                  })}
                </div>
              </div>

              <p className="text-[10px] font-mono text-[#AAA] leading-relaxed bg-[#050505] p-2.5 border border-[#141414]">
                {currentArchetype.severityRationale}
              </p>
            </div>

            {/* Auto-Generated Regex Pattern Preview */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-black uppercase tracking-wider text-white flex items-center gap-1.5">
                  <Hash className="w-3 h-3 text-[#00FF41]" />
                  <span>Expressão Regular Gerada</span>
                </span>
                <button
                  type="button"
                  onClick={handleCopyPattern}
                  className="text-[9px] font-mono uppercase text-[#888] hover:text-white flex items-center gap-1 cursor-pointer"
                >
                  {copiedRegex ? <Check className="w-3 h-3 text-[#00FF41]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedRegex ? 'COPIADO!' : 'COPIAR REGEX'}</span>
                </button>
              </div>

              <div className="p-3 bg-[#000] border border-[#222] font-mono text-xs text-[#00FF41] break-all select-all relative group">
                <span className="text-[#666]">/</span>
                <span className="font-bold text-[#00FF41]">{generatedPattern}</span>
                <span className="text-[#666]">/{generatedFlags}</span>
              </div>
            </div>

            {/* Live Inline Tester */}
            <div className="p-3.5 bg-[#050505] border border-[#1A1A1A] space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase text-[#888] flex items-center gap-1.5">
                  <Play className="w-3 h-3 text-[#FF3E00]" />
                  <span>Teste Instantâneo de Captura</span>
                </span>
                <button
                  type="button"
                  onClick={() => setLiveTestInput(`const test_secret = "${generatedSample}";`)}
                  className="text-[9px] font-mono text-[#00FF41] hover:underline"
                >
                  Carregar Exemplo
                </button>
              </div>

              <input
                type="text"
                value={liveTestInput}
                onChange={(e) => setLiveTestInput(e.target.value)}
                placeholder="Cole um trecho de código para verificar..."
                className="w-full px-2.5 py-1.5 text-xs bg-[#0A0A0A] border border-[#222] font-mono text-white focus:outline-none focus:border-[#FF3E00]"
              />

              {/* Match Feedback Badge */}
              <div className="flex items-center justify-between text-[11px] font-mono pt-1">
                {liveTestResult.error ? (
                  <span className="text-[#FF3E00] font-bold">ERRO REGEX: {liveTestResult.error}</span>
                ) : liveTestResult.matched ? (
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[#00FF41] font-bold flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" />
                      {liveTestResult.matches.length} CAPTURA(S):
                    </span>
                    {liveTestResult.matches.slice(0, 2).map((m, idx) => (
                      <code key={idx} className="bg-[#141414] text-[#00FF41] px-1.5 py-0.5 border border-[#222] text-[10px]">
                        {m.length > 25 ? `${m.slice(0, 25)}...` : m}
                      </code>
                    ))}
                  </div>
                ) : (
                  <span className="text-[#666]">NENHUMA CORRESPONDÊNCIA</span>
                )}
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="pt-3 border-t border-[#1F1F1F] flex flex-col sm:flex-row items-center gap-2.5">
            <button
              type="button"
              id="btn-add-rule-to-active"
              onClick={handleCreateRule}
              disabled={!ruleName.trim() || !generatedPattern.trim()}
              className="w-full sm:flex-1 py-2.5 px-4 bg-[#00FF41] hover:bg-white text-black font-black uppercase text-xs tracking-[0.15em] flex items-center justify-center gap-2 transition-all shadow-[0_0_12px_rgba(0,255,65,0.25)] cursor-pointer disabled:opacity-40"
            >
              <Plus className="w-4 h-4 stroke-[3]" />
              <span>Adicionar às Regras Ativas</span>
            </button>

            {onSendToPlayground && (
              <button
                type="button"
                onClick={handleSendToLab}
                className="w-full sm:w-auto py-2.5 px-3 bg-[#141414] hover:bg-[#222] text-white border border-[#333] font-mono text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                title="Carregar no Regex Sandbox com Realce Instantâneo e Grupos"
              >
                <Terminal className="w-3.5 h-3.5 text-[#00FF41]" />
                <span>Testar no Regex Sandbox</span>
              </button>
            )}

            {onOpenAdvancedModal && (
              <button
                type="button"
                onClick={handleOpenAdvanced}
                className="w-full sm:w-auto py-2.5 px-3 bg-[#141414] hover:bg-[#222] text-[#AAA] hover:text-white border border-[#333] font-mono text-[10px] font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                title="Abrir formulário manual para detalhes adicionais"
              >
                <span>Refinar no Modal &rarr;</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
