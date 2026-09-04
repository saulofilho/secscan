import { FindingCategory, SeverityLevel, ScanFinding, ApiEndpointFinding } from '../types';

export interface SecurityGlossaryEntry {
  id: string;
  title: string;
  category: FindingCategory | 'ENDPOINT' | 'ENTROPY' | 'GENERAL';
  cwe: {
    id: string;
    name: string;
    url: string;
  };
  owasp: {
    code: string;
    title: string;
    year: string;
  };
  cvssScore: number;
  severity: SeverityLevel;
  summary: string;
  threatScenario: string;
  attackerObjective: string;
  blastRadius: string;
  remediationSteps: string[];
  safePattern: {
    language: string;
    bad: string;
    good: string;
    explanation: string;
  };
  rotationRecommendation: string;
  tags: string[];
}

export const SECURITY_GLOSSARY_ENTRIES: SecurityGlossaryEntry[] = [
  {
    id: 'cloud-credentials',
    title: 'Credenciais de Provedores de Nuvem (Cloud Credentials)',
    category: 'CLOUD_CREDENTIAL',
    cwe: {
      id: 'CWE-798',
      name: 'Use of Hard-coded Credentials',
      url: 'https://cwe.mitre.org/data/definitions/798.html'
    },
    owasp: {
      code: 'A07:2021',
      title: 'Identification and Authentication Failures',
      year: '2021'
    },
    cvssScore: 9.8,
    severity: 'CRITICAL',
    summary: 'Chaves de acesso e segredos estáticos de nuvem (AWS Access Key ID / Secret, GCP Service Account, Azure Client Secret) gravados diretamente no código-fonte.',
    threatScenario: 'Um invasor descobre a chave em um commit acidental no GitHub, pacote NPM distribuído ou artefato de build. Utilizando o CLI da nuvem correspondente, o invasor enumera permissões IAM e assume controle da infraestrutura.',
    attackerObjective: 'Criação de instâncias para mineração de criptomoedas, extração de buckets S3 / GCS com dados de clientes, sequestro de backups e persistência via novas contas IAM.',
    blastRadius: 'Comprometimento total da conta de nuvem, custos financeiros imprevistos de dezenas de milhares de dólares e vazamento massivo de banco de dados e logs.',
    remediationSteps: [
      'Revogue imediatamente a chave exposta no console do provedor (IAM / Cloud Console).',
      'Remova a credencial do código e de todo o histórico do Git com git-filter-repo ou BFG Repo-Cleaner.',
      'Utilize IAM Roles temporárias (AWS IAM Roles for EC2/ECS/EKS, Workload Identity no GCP/Azure) em vez de chaves estáticas de longa duração.',
      'Se variáveis forem estritamente necessárias em desenvolvimento local, armazene-as em arquivos .env ignorados pelo .gitignore ou gerenciadores como Doppler / Vault.'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Chave mestre da AWS fixada no código\nconst s3 = new S3Client({\n  credentials: {\n    accessKeyId: "${'AKIA' + 'IOSFODNN7EXAMPLE'}",\n    secretAccessKey: "${'wJalrXUtnFEMI/K7MDENG' + '/bPxRfiCYEXAMPLEKEY'}"\n  }\n});`,
      good: `// ✅ SEGURO: IAM Role automático ou variáveis de ambiente externas\nimport { fromEnv } from "@aws-sdk/credential-providers-env";\n\nconst s3 = new S3Client({\n  // Busca credenciais dinamicamente via IAM Role / Web Identity\n  credentials: fromEnv()\n});`,
      explanation: 'Utilize o SDK oficial com autenticação automática via metadados da instância (IAM Role) ou variáveis injetadas em tempo de execução pelo container.'
    },
    rotationRecommendation: 'Crie uma nova credencial no console IAM, valide o funcionamento no ambiente de staging, atualize o segredo no orquestrador e desative/exclua a chave antiga imediatamente.',
    tags: ['aws', 'gcp', 'azure', 'iam', 's3', 'secrets', 'cloud']
  },
  {
    id: 'jwt-auth-token',
    title: 'Tokens JWT e Autenticação Estática (JWT Leaks)',
    category: 'AUTH_TOKEN',
    cwe: {
      id: 'CWE-522',
      name: 'Insufficiently Protected Credentials',
      url: 'https://cwe.mitre.org/data/definitions/522.html'
    },
    owasp: {
      code: 'A01:2021',
      title: 'Broken Access Control',
      year: '2021'
    },
    cvssScore: 8.8,
    severity: 'HIGH',
    summary: 'Tokens de autenticação JWT assinados (JSON Web Token), tokens de sessão Bearer ou chaves mestras HMAC incorporados estaticamente em scripts.',
    threatScenario: 'O token JWT exposto possui reivindicações (claims) como "role: admin" ou "sub: user_123". Qualquer indivíduo com acesso ao arquivo pode forjar cabeçalhos Authorization: Bearer e atuar como o usuário legítimo.',
    attackerObjective: 'Bypass de mecanismos de autenticação e MFA (Multi-Factor Authentication), impersonificação de administradores e acesso a endpoints protegidos.',
    blastRadius: 'Se o token pertencer a um usuário com privilégios elevados, o invasor tem acesso irrestrito às APIs e dados confidenciais até que o token expire ou a chave de assinatura seja revogada.',
    remediationSteps: [
      'Invalide a chave secreta de assinatura JWT (JWT_SECRET) no servidor para derrubar todas as sessões ativas caso o segredo tenha vazado.',
      'Defina tempo de vida curto para access tokens (ex.: 15 minutos) e utilize refresh tokens armazenados com segurança em cookies HTTP-Only, SameSite=Strict.',
      'Nunca armazene tokens de teste ou tokens reais dentro de mocks do código em produção.'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Token JWT com claims de produção exposto em código\nconst AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.abcdef123456";\nconst res = await fetch('/api/admin', {\n  headers: { Authorization: \`Bearer \${AUTH_TOKEN}\` }\n});`,
      good: `// ✅ SEGURO: Obtenção dinâmica em runtime via sessão do usuário\nconst userToken = await authProvider.getAccessToken();\nconst res = await fetch('/api/admin', {\n  headers: { Authorization: \`Bearer \${userToken}\` }\n});`,
      explanation: 'Tokens devem ser emitidos dinamicamente por um provedor de identidade (IdP) e trafegados de forma segura, nunca codificados no repositório.'
    },
    rotationRecommendation: 'Rotacione o segredo HMAC ou par de chaves RSA/ECDSA usado para assinar os tokens JWT no serviço de autenticação.',
    tags: ['jwt', 'oauth', 'bearer', 'session', 'token', 'auth']
  },
  {
    id: 'database-uri',
    title: 'Strings de Conexão com Banco de Dados (Database URIs)',
    category: 'DATABASE_URI',
    cwe: {
      id: 'CWE-312',
      name: 'Cleartext Storage of Sensitive Information',
      url: 'https://cwe.mitre.org/data/definitions/312.html'
    },
    owasp: {
      code: 'A02:2021',
      title: 'Cryptographic Failures',
      year: '2021'
    },
    cvssScore: 9.6,
    severity: 'CRITICAL',
    summary: 'URIs de conexão com bancos de dados relacionais ou NoSQL (PostgreSQL, MongoDB, MySQL, Redis) contendo usuário, senha em texto claro, host e porta.',
    threatScenario: 'O invasor copia a URL completa (ex.: postgres://admin:P@ssw0rd123@db.prod.internal:5432/main) e conecta-se diretamente ao banco de dados via cliente SQL.',
    attackerObjective: 'Extração integral de tabelas com dados pessoais (LGPD/GDPR), despejo de senhas com hash, injeção de dados maliciosos ou destruição e ransomware nas tabelas.',
    blastRadius: 'Vazamento catastrófico de dados proprietários, interrupção total das operações da empresa e penalidades legais regulatórias.',
    remediationSteps: [
      'Altere imediatamente a senha do usuário de banco de dados envolvido.',
      'Configure Security Groups e firewalls para restringir conexões estritamente aos IPs dos servidores de aplicação, bloqueando o acesso pela internet pública.',
      'Injere DATABASE_URL exclusivamente via variáveis de ambiente da plataforma de hospedagem ou utilize autenticação sem senha (ex.: AWS IAM DB Authentication).'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Credenciais de banco em texto claro no código\nconst pool = new Pool({\n  connectionString: "postgres://postgres:SuperSecret2026!@production-db.internal:5432/main_db"\n});`,
      good: `// ✅ SEGURO: Injeção por variável de ambiente com verificação preventiva\nconst connectionString = process.env.DATABASE_URL;\nif (!connectionString) {\n  throw new Error("A variável de ambiente DATABASE_URL não foi configurada.");\n}\nconst pool = new Pool({ connectionString });`,
      explanation: 'Utilize variáveis de ambiente ou segredos gerenciados pelo Kubernetes/Cloud Run para montar a string de conexão.'
    },
    rotationRecommendation: 'Crie um novo usuário no banco com permissões mínimas, aplique a nova senha nas variáveis de produção e exclua o usuário comprometido.',
    tags: ['postgres', 'mysql', 'mongodb', 'redis', 'sql', 'database']
  },
  {
    id: 'api-keys',
    title: 'Chaves de API de Terceiros (Third-Party API Keys)',
    category: 'API_KEY',
    cwe: {
      id: 'CWE-200',
      name: 'Exposure of Sensitive Information to an Unauthorized Actor',
      url: 'https://cwe.mitre.org/data/definitions/200.html'
    },
    owasp: {
      code: 'A01:2021',
      title: 'Broken Access Control',
      year: '2021'
    },
    cvssScore: 8.5,
    severity: 'HIGH',
    summary: 'Chaves de integração de serviços externos (Stripe Secret Key, GitHub Personal Access Token, SendGrid, Twilio, OpenAI, Slack Webhooks) presentes no código.',
    threatScenario: 'Robôs automatizados vasculham repositórios públicos e commits em segundos buscando padrões conhecidos (ex.: sk_live_*, ghp_*). As chaves são aproveitadas para fraudes financeiras ou spam.',
    attackerObjective: 'Com chaves do Stripe/Twilio/SendGrid: disparar campanhas massivas de phishing/SMS ou realizar transferências fraudulentas. Com tokens do GitHub: acessar repositórios privados da organização.',
    blastRadius: 'Custos astronômicos com provedores de SMS/Email/LLM, bloqueio de contas corporativas por atividade fraudulenta e vazamento de código proprietário.',
    remediationSteps: [
      'Revogue imediatamente a chave no painel do fornecedor terceiro.',
      'Gere uma nova chave restringindo escopos estritamente necessários (princípio do menor privilégio).',
      'Ative restrições de IP ou referrers HTTP no provedor quando a funcionalidade estiver disponível.',
      'Mantenha as chaves em um cofre de segredos (Secrets Manager).'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Chave secreta de produção do Stripe exposta\nimport Stripe from 'stripe';\nconst stripe = new Stripe('${['sk', 'live', '51M3vB7K9L2xQ4wZ198aB7cDeFgHiJkLmNoPqRsTuVwXyZ'].join('_')}');`,
      good: `// ✅ SEGURO: Chave carregada de forma restrita no lado do servidor\nimport Stripe from 'stripe';\nconst apiKey = process.env.STRIPE_SECRET_KEY;\nif (!apiKey) throw new Error("STRIPE_SECRET_KEY is required");\nconst stripe = new Stripe(apiKey);`,
      explanation: 'Chaves de pagamento e APIs de terceiros devem ser manipuladas exclusivamente no back-end e injetadas como variáveis de ambiente protegidas.'
    },
    rotationRecommendation: 'Acesse o dashboard do fornecedor (ex.: Stripe Dashboard), crie uma nova Restricted Key, substitua no ambiente e revogue a chave antiga.',
    tags: ['stripe', 'github', 'sendgrid', 'twilio', 'openai', 'apikey']
  },
  {
    id: 'private-keys',
    title: 'Chaves Criptográficas Privadas (Private Keys)',
    category: 'PRIVATE_KEY',
    cwe: {
      id: 'CWE-321',
      name: 'Use of Hard-coded Cryptographic Key',
      url: 'https://cwe.mitre.org/data/definitions/321.html'
    },
    owasp: {
      code: 'A02:2021',
      title: 'Cryptographic Failures',
      year: '2021'
    },
    cvssScore: 9.8,
    severity: 'CRITICAL',
    summary: 'Blocos PEM com chaves privadas criptográficas assimétricas (-----BEGIN RSA PRIVATE KEY-----, OpenSSH, EC PRIVATE KEY) armazenados no repositório.',
    threatScenario: 'A chave privada é utilizada para assinar certificados SSL/TLS, decodificar tráfego criptografado ou acessar servidores SSH de produção sem necessidade de senha.',
    attackerObjective: 'Ataques Man-in-the-Middle (MitM) descriptografando comunicações confidenciais, login SSH direto como root e interceptação de pacotes internos.',
    blastRadius: 'Comprometimento irrestrito da confidencialidade e integridade das comunicações e servidores de toda a malha corporativa.',
    remediationSteps: [
      'Revogue imediatamente os certificados SSL/TLS ou chaves SSH autorizadas (authorized_keys) associadas a esta chave privada.',
      'Gere um novo par de chaves forte (Ed25519 ou RSA 4096-bit).',
      'Nunca comite arquivos .pem, .key, .p12 ou id_rsa em repositórios de código.',
      'Utilize SSH Certificate Authorities ou KMS de nuvem (AWS KMS, Cloud HSM) para assinar e decodificar dados sem expor a chave privada.'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Bloco de chave privada RSA gravado em string\nconst PRIVATE_KEY = \`-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m4Fz...\n-----END RSA PRIVATE KEY-----\`;`,
      good: `// ✅ SEGURO: Carregamento a partir de cofre de segredos em disco montado\nimport fs from 'fs';\nconst privateKeyPath = process.env.TLS_KEY_PATH || '/etc/secrets/tls.key';\nconst privateKey = fs.readFileSync(privateKeyPath, 'utf-8');`,
      explanation: 'Chaves privadas devem ser provisionadas via Kubernetes Secrets montados em volume seguro (tmpfs em memória) com permissões restritas chmod 400.'
    },
    rotationRecommendation: 'Remova a chave pública do arquivo ~/.ssh/authorized_keys em todos os servidores e instale uma nova chave gerada com ssh-keygen -t ed25519.',
    tags: ['rsa', 'ssh', 'tls', 'crypto', 'certificate', 'pem']
  },
  {
    id: 'hardcoded-password',
    title: 'Senhas e Segredos em Texto Claro (Hardcoded Passwords)',
    category: 'PASSWORD',
    cwe: {
      id: 'CWE-259',
      name: 'Use of Hard-coded Password',
      url: 'https://cwe.mitre.org/data/definitions/259.html'
    },
    owasp: {
      code: 'A07:2021',
      title: 'Identification and Authentication Failures',
      year: '2021'
    },
    cvssScore: 8.9,
    severity: 'HIGH',
    summary: 'Atribuições literais de variáveis como password, pass, secret, auth com valores literais em arquivos de código ou scripts de migração.',
    threatScenario: 'O desenvolvedor inseriu credenciais padrão para testes ou facilitar deploys e esqueceu de remover antes de fazer merge na branch principal.',
    attackerObjective: 'Autenticação em painéis administrativos, bancos de dados legados ou serviços internos sem necessidade de quebrar hashes.',
    blastRadius: 'Acesso não autorizado às contas de serviço afetadas, persistência e movimentação lateral no ambiente de TI.',
    remediationSteps: [
      'Altere a senha de todas as contas associadas à string identificada.',
      'Implemente políticas de senhas fortes gerenciadas automaticamente (rotação periódica por cofre de senhas).',
      'Remova valores default de senhas no código e exija que sejam fornecidas via ambiente em tempo de inicialização.'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Senha administrativa literal no código\nconst config = {\n  username: "superadmin",\n  password: "MasterPassword2026!"\n};`,
      good: `// ✅ SEGURO: Carregamento mandatário via variáveis protegidas\nconst config = {\n  username: process.env.ADMIN_USERNAME || "admin",\n  password: process.env.ADMIN_PASSWORD // Obrigatório, sem default inseguro\n};`,
      explanation: 'Nunca forneça senhas literais de fallback no código-fonte. A ausência do segredo deve impedir o serviço de inicializar com um erro explícito.'
    },
    rotationRecommendation: 'Troque a senha da conta afetada imediatamente e encerre quaisquer sessões ativas.',
    tags: ['password', 'credentials', 'plaintext', 'security']
  },
  {
    id: 'api-paths',
    title: 'Exposição de Rotas Administrativas e Internas (API Route Leak)',
    category: 'API_PATH',
    cwe: {
      id: 'CWE-285',
      name: 'Improper Authorization',
      url: 'https://cwe.mitre.org/data/definitions/285.html'
    },
    owasp: {
      code: 'A01:2021',
      title: 'Broken Access Control',
      year: '2021'
    },
    cvssScore: 7.5,
    severity: 'MEDIUM',
    summary: 'Rotas de API com palavras-chave críticas (/admin, /internal, /debug, /metrics, /graphql) identificadas em arquivos de front-end ou clientes web públicos.',
    threatScenario: 'O invasor analisa o JavaScript empacotado no navegador do cliente, descobre rotas internas de teste ou administração que não deveriam ser públicas e tenta explorá-las diretamente.',
    attackerObjective: 'Mapear a superfície de ataque da API, explorar vulnerabilidades de controle de acesso (BOLA / IDOR) ou endpoints de debug esquecidos com dados sensíveis.',
    blastRadius: 'Exposição de métricas de telemetria, documentação Swagger/OpenAPI não autenticada e possíveis brechas para escalonamento de privilégios.',
    remediationSteps: [
      'Assegure que rotas administrativas e internas estejam protegidas por autenticação robusta e autorização baseada em papéis (RBAC).',
      'Não exponha rotas internas em clientes públicos de front-end.',
      'Desative endpoints de /debug, /actuator ou /metrics na internet pública (deixe acessíveis apenas via VPN ou rede interna).'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Cliente web acessando rotas de debug ou admin sem validação\nfetch('/api/v1/internal/admin/drop-database', { method: 'POST' });`,
      good: `// ✅ SEGURO: Endpoints administrativos restritos a rede interna e protegidos por middleware RBAC\nrouter.post('/admin/action', verifyJwt, requireRole(['SUPERADMIN']), handleAdminAction);`,
      explanation: 'Proteja todas as rotas com middlewares de autorização explícitos e restrinja endpoints operacionais à rede interna (VPC).'
    },
    rotationRecommendation: 'Revise as permissões do Reverse Proxy (Nginx/Kong/Cloudflare) para bloquear acesso externo a caminhos /admin/* e /internal/*.',
    tags: ['routes', 'endpoints', 'rbac', 'admin', 'internal', 'api']
  },
  {
    id: 'high-entropy-string',
    title: 'Strings de Alta Entropia de Shannon (High-Entropy Secrets)',
    category: 'CUSTOM_REGEX',
    cwe: {
      id: 'CWE-312',
      name: 'Cleartext Storage of Sensitive Information',
      url: 'https://cwe.mitre.org/data/definitions/312.html'
    },
    owasp: {
      code: 'A02:2021',
      title: 'Cryptographic Failures',
      year: '2021'
    },
    cvssScore: 8.0,
    severity: 'HIGH',
    summary: 'Sequências alfanuméricas com distribuição pseudoaleatória e alta entropia de Shannon (ex.: acima de 4.5 bits/char), características de tokens ou chaves criptográficas não catalogadas.',
    threatScenario: 'Uma string aleatória de alta entropia geralmente representa um segredo proprietário, token de sessão proprietário ou chave privada sem formato prefixado conhecido.',
    attackerObjective: 'Decodificação ou utilização do token em APIs internas da aplicação.',
    blastRadius: 'Varia conforme o serviço ao qual o token pertence (desde acesso a microsserviços internos até segredos de criptografia simétrica).',
    remediationSteps: [
      'Investigue qual subsistema gera ou consome a string identificada.',
      'Substitua a string por carregamento dinâmico a partir de variáveis de ambiente.',
      'Adicione regras customizadas para formalizar o padrão de detecção da sua empresa.'
    ],
    safePattern: {
      language: 'typescript',
      bad: `// ❌ INSEGURO: Token customizado aleatório de alta entropia fixado no código\nconst INTERNAL_HMAC_SALT = "8f4b13a9c72e04d6a8f152e93b47c012";`,
      good: `// ✅ SEGURO: Carregamento do sal ou chave a partir de variável protegida\nconst INTERNAL_HMAC_SALT = process.env.APP_ENCRYPTION_SALT;\nif (!INTERNAL_HMAC_SALT) throw new Error("APP_ENCRYPTION_SALT is missing");`,
      explanation: 'Mesmo segredos internos que não possuem prefixos conhecidos (como AWS ou Stripe) devem ser mantidos fora do código-fonte.'
    },
    rotationRecommendation: 'Rotacione o token de acordo com o protocolo do serviço interno proprietário associado.',
    tags: ['entropy', 'shannon', 'random', 'secret', 'tokens']
  }
];

/**
 * Maps a finding or endpoint to the most relevant security glossary entry
 */
export function getGlossaryEntryForFinding(finding: ScanFinding): SecurityGlossaryEntry {
  const category = finding.category;
  const ruleName = (finding.ruleName || '').toLowerCase();
  const matched = (finding.matchedSecret || '').toLowerCase();

  // Rule Name & Pattern heuristics
  if (
    category === 'CLOUD_CREDENTIAL' || 
    ruleName.includes('aws') || 
    ruleName.includes('gcp') || 
    ruleName.includes('azure') ||
    matched.startsWith('akia')
  ) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'cloud-credentials')!;
  }

  if (
    category === 'AUTH_TOKEN' || 
    ruleName.includes('jwt') || 
    ruleName.includes('bearer') ||
    matched.startsWith('eyj')
  ) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'jwt-auth-token')!;
  }

  if (
    category === 'DATABASE_URI' || 
    ruleName.includes('postgres') || 
    ruleName.includes('mysql') || 
    ruleName.includes('mongo') || 
    ruleName.includes('redis') ||
    matched.includes('postgres://') ||
    matched.includes('mongodb://')
  ) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'database-uri')!;
  }

  if (
    category === 'PRIVATE_KEY' || 
    ruleName.includes('rsa') || 
    ruleName.includes('private key') || 
    ruleName.includes('ssh') ||
    matched.includes('begin rsa') ||
    matched.includes('begin private')
  ) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'private-keys')!;
  }

  if (
    category === 'API_KEY' || 
    ruleName.includes('stripe') || 
    ruleName.includes('github') || 
    ruleName.includes('slack') || 
    ruleName.includes('openai') ||
    matched.startsWith('sk_live') ||
    matched.startsWith('ghp_')
  ) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'api-keys')!;
  }

  if (
    category === 'PASSWORD' || 
    ruleName.includes('password') || 
    ruleName.includes('senha')
  ) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'hardcoded-password')!;
  }

  if (category === 'API_PATH' || ruleName.includes('route') || ruleName.includes('endpoint')) {
    return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'api-paths')!;
  }

  // Fallback to high-entropy or general
  return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'high-entropy-string') || SECURITY_GLOSSARY_ENTRIES[0];
}

/**
 * Maps an API endpoint finding to glossary
 */
export function getGlossaryEntryForEndpoint(endpoint: ApiEndpointFinding): SecurityGlossaryEntry {
  return SECURITY_GLOSSARY_ENTRIES.find(e => e.id === 'api-paths')!;
}
