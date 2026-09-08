import { FindingCategory, SeverityLevel, ScanFinding } from '../types';

export interface RemediationStep {
  stepNumber: number;
  title: string;
  description: string;
  commandOrSnippet?: string;
  commandType?: 'bash' | 'typescript' | 'sql' | 'env' | 'none';
  keyTakeaway: string;
}

export interface RemediationWikiGuide {
  id: string;
  title: string;
  category: FindingCategory | 'ENDPOINT' | 'ENTROPY';
  applicableRuleIds: string[];
  severity: SeverityLevel;
  cvssScore: number;
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
  summary: string;
  threatScenario: string;
  blastRadius: string;
  stepByStepPatching: RemediationStep[];
  beforeAfterCode: {
    language: string;
    before: string;
    after: string;
    explanation: string;
  };
  gitHistoryPurge: {
    command: string;
    warning: string;
  };
  secretRotationGuide: string;
  preventativeMeasures: string[];
  tags: string[];
}

export const REMEDIATION_WIKI_GUIDES: RemediationWikiGuide[] = [
  {
    id: 'cloud-credentials-aws',
    title: 'Credenciais e Chaves de Acesso AWS (Access Key ID & Secret)',
    category: 'CLOUD_CREDENTIAL',
    applicableRuleIds: ['sec-aws-akid', 'sec-aws-secret'],
    severity: 'CRITICAL',
    cvssScore: 9.8,
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
    summary: 'Chaves de acesso permanentes (AKIA...) e segredos da AWS embutidos no código-fonte permitem controle total sobre recursos de nuvem.',
    threatScenario: 'Robôs automatizados varrem repositórios e artefatos em segundos. Com a chave, atacantes provisionam instâncias caras para mineração de criptomoedas, extraem buckets S3 com dados de clientes e criam usuários de persistência.',
    blastRadius: 'Comprometimento total da conta de nuvem, custos financeiros de centenas de milhares de dólares e vazamento de bases de dados.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Contenção Imediata: Desativar a Chave no AWS IAM',
        description: 'Acesse o console AWS IAM ou utilize o AWS CLI com uma conta administrativa para inativar a chave comprometida imediatamente.',
        commandOrSnippet: 'aws iam update-access-key --access-key-id AKIA_EXEMPLO_DETECTADO --status Inactive',
        commandType: 'bash',
        keyTakeaway: 'Inative a chave antes de deletar para validar se serviços em produção não serão derrubados inesperadamente.'
      },
      {
        stepNumber: 2,
        title: 'Migração de Código: Utilizar IAM Roles ou Variáveis de Ambiente',
        description: 'Remova as chaves estáticas do código. Em ambientes EC2/ECS/EKS/Lambda, use IAM Roles automáticas. Em desenvolvimento local, use variáveis injetadas.',
        commandOrSnippet: `# .env (adicionado ao .gitignore)\nAWS_REGION=us-east-1\n# No container ou EC2, não declare chaves: a Role cuidará disso!`,
        commandType: 'env',
        keyTakeaway: 'O SDK da AWS (v3) detecta credenciais automaticamente da instância através do provider chain padrão.'
      },
      {
        stepNumber: 3,
        title: 'Expurgo do Histórico Git',
        description: 'Mesmo que você remova o commit, o segredo permanece no histórico. Use git-filter-repo para purgar a credencial de todos os commits e branches.',
        commandOrSnippet: 'git filter-repo --replace-text <(echo "AKIA_EXEMPLO_DETECTADO==>REMOVED_SECRET")',
        commandType: 'bash',
        keyTakeaway: 'Requer force push (git push --force --all) e aviso prévio para os outros desenvolvedores re-clonarem o repositório.'
      },
      {
        stepNumber: 4,
        title: 'Auditoria no CloudTrail para Identificar Atividades Maliciosas',
        description: 'Verifique se a chave realizou chamadas não autorizadas (ex.: RunInstances, CreateUser, PutBucketPolicy) nas últimas horas.',
        commandOrSnippet: 'aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA_EXEMPLO_DETECTADO',
        commandType: 'bash',
        keyTakeaway: 'Audite a criação de usuários IAM clandestinos ou políticas criadas para garantir persistência.'
      },
      {
        stepNumber: 5,
        title: 'Exclusão Definitiva da Chave Comprometida',
        description: 'Após confirmar que a nova Role ou chave rotacionada está funcionando sem interrupções, exclua a chave antiga.',
        commandOrSnippet: 'aws iam delete-access-key --access-key-id <SUA_CHAVE_AWS_ANTIGA>',
        commandType: 'bash',
        keyTakeaway: 'Nunca reative uma chave que já foi exposta publicamente.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Credenciais permanentes da AWS gravadas no arquivo\nimport { S3Client } from "@aws-sdk/client-s3";\n\nconst s3 = new S3Client({\n  region: "us-east-1",\n  credentials: {\n    accessKeyId: process.env.AWS_ACCESS_KEY_ID || "<SUA_AWS_ACCESS_KEY_ID>",\n    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || "<SUA_AWS_SECRET_ACCESS_KEY>"\n  }\n});`,
      after: `// ✅ SEGURO: IAM Role nativo do SDK (sem credenciais em código)\nimport { S3Client } from "@aws-sdk/client-s3";\n\n// O SDK resolve credenciais automaticamente via IAM Role, IRSA ou env vars\nconst s3 = new S3Client({\n  region: process.env.AWS_REGION || "us-east-1"\n});`,
      explanation: 'O SDK v3 do Node.js utiliza a cadeia de credenciais padrão, obtendo tokens temporários sem expor segredos.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --invert-paths --path .env\n# ou substituir string específica:\npython3 -m pip install git-filter-repo\ngit filter-repo --replace-text replacements.txt',
      warning: 'Atenção: A reescrita do histórico altera todos os SHAs de commit. Comunique a equipe antes de forçar o push.'
    },
    secretRotationGuide: 'Console AWS > IAM > Users > Security Credentials > Create Access Key (ou prefira IAM Identity Center / Roles temporárias).',
    preventativeMeasures: [
      'Bloqueie commits contendo padrões AKIA via pre-commit hook (Husky + SecScan CLI).',
      'Ative o AWS GuardDuty para detecção de credenciais expostas no GitHub.',
      'Configure SCP (Service Control Policies) restringindo regiões permitidas para evitar surpresas financeiras.'
    ],
    tags: ['aws', 'iam', 's3', 'ec2', 'cloud', 'sts', 'credentials']
  },
  {
    id: 'cloud-credentials-gcp',
    title: 'Chaves de API Google Cloud & Gemini (AIza...)',
    category: 'API_KEY',
    applicableRuleIds: ['sec-google-api'],
    severity: 'HIGH',
    cvssScore: 8.5,
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
    summary: 'Chaves com formato AIza... dão acesso a serviços de IA (Gemini), Maps, Translation e infraestrutura Google Cloud.',
    threatScenario: 'Atacantes usam sua chave para consumir cotas gratuitas e pagas de modelos Gemini Flash/Pro, inflando faturas de IA ou acessando buckets de storage.',
    blastRadius: 'Cobrança excessiva de tokens de LLM, esgotamento de cotas de APIs corporativas e bloqueio do projeto por abuso.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Restringir a Chave no Google Cloud Console',
        description: 'Vá em APIs & Services > Credentials. Em "API restrictions", restrinja a chave estritamente aos serviços necessários (ex.: Gemini API). Em "Application restrictions", configure restrição de IP ou HTTP Referrers.',
        commandOrSnippet: '# No Google Cloud Console:\nAPIs & Services > Credentials > Edit Key > API Restrictions > Restrict key',
        commandType: 'none',
        keyTakeaway: 'Uma chave restrita a IPs do seu backend não pode ser usada por invasores fora do servidor.'
      },
      {
        stepNumber: 2,
        title: 'Migração para Chamadas Server-Side (/api/gemini)',
        description: 'Nunca invoque @google/genai diretamente no cliente browser. Crie uma rota proxy no servidor Express/Fastify.',
        commandOrSnippet: `// server/routes/ai.ts\nimport { GoogleGenAI } from '@google/genai';\nconst ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });`,
        commandType: 'typescript',
        keyTakeaway: 'O frontend se comunica apenas com a sua rota interna autenticada, mantendo o GEMINI_API_KEY oculto.'
      },
      {
        stepNumber: 3,
        title: 'Geração de Nova Chave e Revogação da Comprometida',
        description: 'Crie uma nova chave de API no Google Cloud Console, atualize a variável GEMINI_API_KEY em produção e delete a chave antiga.',
        commandOrSnippet: 'gcloud services api-keys delete [KEY_ID]',
        commandType: 'bash',
        keyTakeaway: 'Não delete a chave antes de validar a nova para evitar downtime na aplicação.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Chave do Gemini em código frontend React/Vite\nimport { GoogleGenAI } from "@google/genai";\nconst ai = new GoogleGenAI({ apiKey: "<SUA_CHAVE_GEMINI_AQUI>" });`,
      after: `// ✅ SEGURO: Frontend faz requisição para endpoint backend protegido\nconst response = await fetch('/api/analyze', {\n  method: 'POST',\n  headers: { 'Content-Type': 'application/json' },\n  body: JSON.stringify({ prompt })\n});`,
      explanation: 'Centralize chamadas de IA no servidor para proteger cotas e monitorar abusos.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "CHAVE_GEMINI_EXPOSTA==>[REDACTED_GEMINI_KEY]")',
      warning: 'Certifique-se de invalidar a chave no console GCP antes do expurgo.'
    },
    secretRotationGuide: 'GCP Console > APIs & Services > Credentials > Create Credentials > API Key. Aplique restrições imediatamente.',
    preventativeMeasures: [
      'Use Workload Identity Federation para autenticação entre GitHub Actions e Google Cloud sem chaves.',
      'Configure alertas de orçamento (Budget Alerts) no Google Cloud Billing.'
    ],
    tags: ['gemini', 'gcp', 'google', 'ai', 'apikey', 'cloud']
  },
  {
    id: 'auth-token-github',
    title: 'Tokens de Acesso Pessoal GitHub (PAT / ghp_ / github_pat_)',
    category: 'AUTH_TOKEN',
    applicableRuleIds: ['sec-github-pat'],
    severity: 'CRITICAL',
    cvssScore: 9.6,
    cwe: {
      id: 'CWE-522',
      name: 'Insufficiently Protected Credentials',
      url: 'https://cwe.mitre.org/data/definitions/522.html'
    },
    owasp: {
      code: 'A07:2021',
      title: 'Identification and Authentication Failures',
      year: '2021'
    },
    summary: 'Tokens com prefixo ghp_ ou github_pat_ concedem acesso a repositórios privados, workflows de CI/CD e pacotes da organização.',
    threatScenario: 'O atacante clona todo o código proprietário da organização, injeta backdoors em branches protegidas ou extrai segredos dos GitHub Actions.',
    blastRadius: 'Vazamento integral de propriedade intelectual corporativa e cadeia de suprimentos (Supply Chain Poisoning).',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Revogar o Token Imediatamente',
        description: 'Acesse GitHub > Settings > Developer Settings > Personal Access Tokens (Tokens classic ou Fine-grained) e clique em "Revoke".',
        commandOrSnippet: 'gh auth logout || # Acesse: https://github.com/settings/tokens',
        commandType: 'bash',
        keyTakeaway: 'A revogação no GitHub tem efeito instantâneo em todas as APIs e operações git.'
      },
      {
        stepNumber: 2,
        title: 'Substituir por GitHub Apps ou GITHUB_TOKEN nos Workflows',
        description: 'Em pipelines de CI/CD, nunca use PATs pessoais. Use o segredo automático secrets.GITHUB_TOKEN com permissões mínimas.',
        commandOrSnippet: `permissions:\n  contents: read\n  packages: write`,
        commandType: 'bash',
        keyTakeaway: 'O GITHUB_TOKEN é gerado dinamicamente para cada execução e expira logo após a conclusão do job.'
      },
      {
        stepNumber: 3,
        title: 'Auditar o Audit Log da Organização',
        description: 'Verifique quais repositórios foram clonados ou alterados pelo token nas últimas 48 horas em Settings > Audit Log.',
        commandOrSnippet: 'action:repo.create OR action:repo.download_zip',
        commandType: 'none',
        keyTakeaway: 'Confirme se não houve criação de Webhooks maliciosos para servidores externos.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: PAT do GitHub para clonagem de dependências\nconst repoUrl = "https://<GITHUB_PAT_TOKEN>@github.com/empresa/private-lib.git";`,
      after: `// ✅ SEGURO: Chave SSH de Deploy Key ou GitHub Actions Token\n// No pipeline de CI/CD, utilize a variável nativa:\nconst token = process.env.GITHUB_TOKEN;\nconst headers = { Authorization: \`Bearer \${token}\` };`,
      explanation: 'Utilize Deploy Keys restritas por repositório ou tokens de curta duração gerenciados pelo CI/CD.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "TOKEN_PAT_VAZADO==>[REVOKED_PAT]")',
      warning: 'Tokens clássicos do GitHub são revogados automaticamente pelo GitHub Secret Scanning se detectados em repositório público.'
    },
    secretRotationGuide: 'GitHub > Settings > Developer Settings > Personal access tokens > Fine-grained tokens. Defina expiração máxima de 30 dias.',
    preventativeMeasures: [
      'Exija aprovação de administradores para emissão de PATs com acesso a repositórios da organização.',
      'Ative o GitHub Secret Scanning e Push Protection em toda a organização.'
    ],
    tags: ['github', 'pat', 'git', 'ci-cd', 'devops', 'tokens']
  },
  {
    id: 'api-key-stripe',
    title: 'Chaves Secretas Stripe (sk_live_ / rk_live_)',
    category: 'API_KEY',
    applicableRuleIds: ['sec-stripe-secret'],
    severity: 'CRITICAL',
    cvssScore: 9.5,
    cwe: {
      id: 'CWE-312',
      name: 'Cleartext Storage of Sensitive Information',
      url: 'https://cwe.mitre.org/data/definitions/312.html'
    },
    owasp: {
      code: 'A01:2021',
      title: 'Broken Access Control',
      year: '2021'
    },
    summary: 'Chaves com prefixo sk_live_ ou rk_live_ permitem realizar estornos, transferir fundos, criar cobranças e extrair dados de clientes (PII/PCI).',
    threatScenario: 'Um atacante que obtém a sk_live_ pode emitir reembolsos fraudulentos para contas controladas, aplicar golpes de teste de cartões clonados ou baixar relatórios fiscais.',
    blastRadius: 'Prejuízo financeiro direto, multas por violação do padrão PCI-DSS e bloqueio da conta bancária Stripe.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Criar Nova Restricted Key e Revogar a Chave Antiga no Dashboard',
        description: 'Acesse o Stripe Dashboard > Developers > API Keys. Crie uma nova "Restricted Key" concedendo apenas as permissões necessárias (ex: Charges: Write, Customers: Read). Em seguida, agende a revogação da chave antiga.',
        commandOrSnippet: 'https://dashboard.stripe.com/apikeys',
        commandType: 'none',
        keyTakeaway: 'O Stripe permite definir uma janela de 12 horas para a chave antiga continuar funcionando enquanto você faz o deploy.'
      },
      {
        stepNumber: 2,
        title: 'Isolar Exclusivamente no Backend via Variável de Ambiente',
        description: 'No frontend, utilize APENAS a chave publicável (pk_live_). A chave secreta (sk_live_) NUNCA deve ser incluída no build React/Vite.',
        commandOrSnippet: `// .env do backend (NÃO comitar no git)\nSTRIPE_SECRET_KEY=rk_live_NOVA_CHAVE_RESTRITA_GERADA\n\n// .env do frontend\nVITE_STRIPE_PUBLISHABLE_KEY=pk_live_CHAVE_PUBLICA_OK`,
        commandType: 'env',
        keyTakeaway: 'Somente variáveis com prefixo VITE_ são expostas ao browser no Vite.'
      },
      {
        stepNumber: 3,
        title: 'Auditar o Registro de Eventos e Pagamentos Recentes',
        description: 'Verifique no Dashboard > Developers > Logs se chamadas de API foram efetuadas de IPs desconhecidos.',
        commandOrSnippet: 'Filtre logs por: source: API e status: 200 nas últimas 72h',
        commandType: 'none',
        keyTakeaway: 'Identifique estornos ou pagamentos com valores suspeitos imediatamente.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Chave secreta de produção no cliente ou exposta\nimport Stripe from 'stripe';\nconst stripe = new Stripe('<SUA_STRIPE_SECRET_KEY>');`,
      after: `// ✅ SEGURO: Chave injetada no servidor via cofre ou variável protegida\nimport Stripe from 'stripe';\nconst apiKey = process.env.STRIPE_SECRET_KEY;\nif (!apiKey) throw new Error("STRIPE_SECRET_KEY é obrigatório");\nconst stripe = new Stripe(apiKey);`,
      explanation: 'Chaves secretas devem residir estritamente no runtime Node.js/Express, nunca no bundle do browser.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "CHAVE_STRIPE_VAZADA==>[REDACTED_STRIPE_KEY]")',
      warning: 'Após o expurgo, force push no branch principal e comunique a equipe.'
    },
    secretRotationGuide: 'Stripe Dashboard > Developers > API Keys > "Roll key..." (permite rotação gradual sem downtime).',
    preventativeMeasures: [
      'Prefira Restricted Keys (rk_live_) com escopos granulares em vez da Secret Key padrão (sk_live_).',
      'Ative a proteção Radar do Stripe contra fraudes de teste de cartão.'
    ],
    tags: ['stripe', 'payments', 'pci-dss', 'financial', 'secret', 'apikey']
  },
  {
    id: 'auth-token-jwt',
    title: 'Tokens JWT e Segredos HMAC (JSON Web Tokens)',
    category: 'AUTH_TOKEN',
    applicableRuleIds: ['sec-jwt-token'],
    severity: 'HIGH',
    cvssScore: 8.8,
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
    summary: 'Tokens JWT estáticos assinados incorporados em arquivos contêm claims de usuários e permissões administrativas.',
    threatScenario: 'O atacante extrai o token JWT e usa o cabeçalho Authorization: Bearer para impersonar a conta associada ao sub/role no backend sem precisar de senha ou MFA.',
    blastRadius: 'Acesso completo como o usuário ou administrador dono do token até que este expire ou o segredo de assinatura seja invalidado.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Rotacionar o JWT_SECRET no Servidor de Autenticação',
        description: 'Se o token vazado possui privilégios de administrador ou longa validade, altere imediatamente o JWT_SECRET do servidor para invalidar todas as sessões ativas.',
        commandOrSnippet: 'openssl rand -base64 48 # Gera novo segredo criptográfico robusto',
        commandType: 'bash',
        keyTakeaway: 'Ao trocar o segredo HMAC, todos os tokens emitidos anteriormente serão rejeitados com erro de assinatura inválida.'
      },
      {
        stepNumber: 2,
        title: 'Remover Tokens Estáticos de Mocks e Testes',
        description: 'Substitua tokens estáticos no código por fluxos dinâmicos de autenticação ou geração de tokens simulados em tempo de execução de testes.',
        commandOrSnippet: `// Em testes, gere um token em memória:\nconst testToken = jwt.sign({ sub: 'user_1' }, 'test-secret', { expiresIn: '5m' });`,
        commandType: 'typescript',
        keyTakeaway: 'Nunca utilize tokens com dados reais de produção em arquivos de teste comitados.'
      },
      {
        stepNumber: 3,
        title: 'Armazenamento Seguro de Tokens (Cookies HTTP-Only)',
        description: 'No frontend, não armazene JWTs em localStorage (suscetível a roubo via XSS). Prefira cookies HTTP-Only com flag SameSite=Strict.',
        commandOrSnippet: `res.cookie('token', jwtToken, {\n  httpOnly: true,\n  secure: process.env.NODE_ENV === 'production',\n  sameSite: 'strict'\n});`,
        commandType: 'typescript',
        keyTakeaway: 'Cookies HTTP-Only não podem ser lidos por JavaScript no navegador, neutralizando ataques XSS.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Token JWT codificado fixo no código\nconst AUTH_TOKEN = "Bearer eyJhbGciOi...[JWT_HEADER].[JWT_PAYLOAD].[JWT_SIGNATURE]";\nconst res = await fetch('/api/admin', { headers: { Authorization: AUTH_TOKEN } });`,
      after: `// ✅ SEGURO: Token obtido dinamicamente após login\nconst token = await authContext.getValidAccessToken();\nconst res = await fetch('/api/admin', {\n  headers: { Authorization: \`Bearer \${token}\` }\n});`,
      explanation: 'Tokens devem ser gerados em runtime mediante autenticação e possuir TTL reduzido.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "TOKEN_JWT_VAZADO==>[EXPIRED_TOKEN]")',
      warning: 'Rotacione o segredo de assinatura para garantir invalidação mesmo se o histórico for copiado.'
    },
    secretRotationGuide: 'Atualize a variável JWT_SECRET ou chave privada RSA/ECDSA nas configurações do cluster de autenticação.',
    preventativeMeasures: [
      'Defina tempo de vida curto para access tokens (máximo 15 minutos) com rotação automática via refresh token.',
      'Utilize algoritmos assimétricos (RS256/ES256) onde o frontend possui apenas a chave pública para validar.'
    ],
    tags: ['jwt', 'oauth', 'token', 'session', 'auth', 'hmac']
  },
  {
    id: 'database-uri-all',
    title: 'Strings de Conexão com Banco de Dados (PostgreSQL, MongoDB, MySQL, Redis)',
    category: 'DATABASE_URI',
    applicableRuleIds: ['sec-db-uri'],
    severity: 'CRITICAL',
    cvssScore: 9.8,
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
    summary: 'URIs como postgresql://user:password@host:port/db expõem credenciais de superusuário ou leitura/escrita do banco de dados.',
    threatScenario: 'O atacante se conecta diretamente à porta 5432/27017/3306 do banco de dados na internet, faz download de todas as tabelas, apaga os dados ou instala um ransomware exigindo resgate.',
    blastRadius: 'Vazamento massivo de banco de dados (LGPD/GDPR), paralisação da empresa e perda irreversível de dados.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Trocar a Senha do Usuário do Banco Imediatamente',
        description: 'Acesse o console do banco (psql, mongosh, mysql) e altere a senha do usuário comprometido.',
        commandOrSnippet: `ALTER USER nome_usuario WITH PASSWORD 'NovaSenhaForteSuperSegura2026!';`,
        commandType: 'sql',
        keyTakeaway: 'Derrube conexões ativas do usuário antigo para desconectar invasores que já possam estar logados.'
      },
      {
        stepNumber: 2,
        title: 'Restringir o Acesso por Rede (Firewall / Security Group)',
        description: 'Bancos de dados NUNCA devem estar abertos para 0.0.0.0/0 na internet pública. Restrinja as portas exclusivamente para a VPC ou IPs dos servidores de aplicação.',
        commandOrSnippet: `# Exemplo de Security Group na AWS / GCP:\nPermitir entrada TCP 5432 APENAS do Security Group do App ou IP fixo da VPN`,
        commandType: 'none',
        keyTakeaway: 'Mesmo que a senha vaze, o invasor não conseguirá alcançar a porta do banco de fora da rede privada.'
      },
      {
        stepNumber: 3,
        title: 'Injetar DATABASE_URL via Variável de Ambiente',
        description: 'Mova a string para o arquivo .env (ignorado no .gitignore) ou segredo no Cloud Run / Kubernetes / Heroku.',
        commandOrSnippet: `DATABASE_URL="postgresql://app_user:NovaSenhaForte@db-internal.empresa.com:5432/producao?sslmode=require"`,
        commandType: 'env',
        keyTakeaway: 'Exija sempre sslmode=require para criptografar o tráfego entre a aplicação e o banco.'
      },
      {
        stepNumber: 4,
        title: 'Criar Usuários com Menor Privilégio',
        description: 'Nunca utilize o usuário root ou postgres na aplicação. Crie um usuário com permissões restritas às tabelas necessárias.',
        commandOrSnippet: `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;`,
        commandType: 'sql',
        keyTakeaway: 'Evite conceder DROP TABLE, ALTER DATABASE ou SUPERUSER ao usuário da aplicação web.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: URI com credenciais de produção no código\nimport { Pool } from 'pg';\nconst pool = new Pool({\n  connectionString: 'postgres://postgres:<SENHA_SECRETA_REMOVIDA>@db.prod.internal:5432/main'\n});`,
      after: `// ✅ SEGURO: Conexão via variável de ambiente obrigatória\nimport { Pool } from 'pg';\nconst connectionString = process.env.DATABASE_URL;\nif (!connectionString) throw new Error("DATABASE_URL is missing");\nconst pool = new Pool({ connectionString, ssl: { rejectUnauthorized: true } });`,
      explanation: 'Use variáveis de ambiente e valide a presença da connection string durante o bootstrap da aplicação.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "SENHA_DO_BANCO==>[REMOVED_DB_PASSWORD]")',
      warning: 'Verifique se não há outros arquivos de migração ou seeds com credenciais antes de forçar o push.'
    },
    secretRotationGuide: 'Altere a senha no SGDB, atualize a variável DATABASE_URL no serviço de deploy e reinicie a aplicação.',
    preventativeMeasures: [
      'Adote autenticação sem senha (ex.: AWS IAM Database Authentication para RDS Aurora).',
      'Utilize conexões intermediadas por poolers como PgBouncer com TLS mútuo.'
    ],
    tags: ['database', 'postgres', 'mysql', 'mongodb', 'redis', 'sql', 'uri']
  },
  {
    id: 'private-key-crypto',
    title: 'Chaves Criptográficas Privadas (RSA, SSH, OpenSSH, PEM)',
    category: 'PRIVATE_KEY',
    applicableRuleIds: ['sec-private-key'],
    severity: 'CRITICAL',
    cvssScore: 9.8,
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
    summary: 'Blocos com cabeçalhos de chave privada assimétrica (RSA, OPENSSH, PEM) conferem acesso direto a servidores SSH ou capacidade de assinar certificados.',
    threatScenario: 'O atacante faz login como root em servidores de produção via SSH sem senha, decifra pacotes de rede criptografados ou emite certificados TLS falsificados.',
    blastRadius: 'Comprometimento irrestrito de servidores, containers e comunicação segura de toda a infraestrutura corporativa.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Remover a Chave Pública de authorized_keys nos Servidores',
        description: 'Acesse imediatamente os servidores afetados e remova a chave pública correspondente do arquivo ~/.ssh/authorized_keys.',
        commandOrSnippet: `ssh-keygen -l -f /caminho/chave_vazada.pem # Descubra o fingerprint\nsed -i '/fingerprint_ou_comentario/d' ~/.ssh/authorized_keys`,
        commandType: 'bash',
        keyTakeaway: 'Sem a chave pública em authorized_keys, a chave privada vazada torna-se inútil para login SSH.'
      },
      {
        stepNumber: 2,
        title: 'Gerar um Novo Par de Chaves Forte (Ed25519)',
        description: 'Gere um novo par de chaves usando o algoritmo moderno Ed25519 com senha forte (passphrase).',
        commandOrSnippet: `ssh-keygen -t ed25519 -C "admin@empresa.com.br" -f ~/.ssh/id_ed25519_new`,
        commandType: 'bash',
        keyTakeaway: 'O algoritmo Ed25519 é mais seguro, rápido e conciso do que RSA 2048/4096 bits.'
      },
      {
        stepNumber: 3,
        title: 'Proteger Arquivos de Chave no .gitignore',
        description: 'Adicione regras no .gitignore global para impedir que arquivos de chave privada sejam comitados por engano.',
        commandOrSnippet: `# Adicione ao .gitignore:\n*.pem\n*.key\n*.p12\n*.pkcs12\nid_rsa\nid_ed25519`,
        commandType: 'none',
        keyTakeaway: 'Chaves privadas devem ser injetadas via SSH Agent ou montadas via volumes de tmpfs em memória.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Bloco de chave privada gravado em string literal no código\nconst PRIVATE_KEY = "-----" + "BEGIN [RSA] PRIVATE KEY" + "-----\\n[CONTEUDO_DA_CHAVE_PRIVADA_REMOVIDO]\\n-----" + "END [RSA] PRIVATE KEY" + "-----";`,
      after: `// ✅ SEGURO: Carregamento a partir de cofre montado no disco em runtime\nimport fs from 'fs';\nconst keyPath = process.env.SSH_KEY_PATH || '/etc/secrets/ssh.key';\nconst privateKey = fs.readFileSync(keyPath, 'utf8');`,
      explanation: 'Utilize volumes protegidos com permissão de leitura restrita (chmod 400) ou serviços KMS.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --invert-paths --path caminho/da/chave.pem',
      warning: 'Arquivos de chave privada comitados no Git devem ser considerados irrevogavelmente comprometidos.'
    },
    secretRotationGuide: 'Substitua as chaves no bastion host e servidores internos, e revogue certificados SSL/TLS se a chave for de CA/TLS.',
    preventativeMeasures: [
      'Utilize SSH Certificate Authorities (SSH CA) ou HashiCorp Vault para emitir certificados SSH efêmeros válidos por algumas horas.',
      'Bloqueie login por senha nos servidores e desative o login direto de root via SSH.'
    ],
    tags: ['ssh', 'rsa', 'pem', 'ed25519', 'crypto', 'private-key', 'pki']
  },
  {
    id: 'password-hardcoded',
    title: 'Senhas e Segredos Literais em Código (Hardcoded Passwords)',
    category: 'PASSWORD',
    applicableRuleIds: ['sec-hardcoded-pass'],
    severity: 'HIGH',
    cvssScore: 8.9,
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
    summary: 'Atribuições estáticas de strings a variáveis como password, client_secret ou db_pass em arquivos JS/TS.',
    threatScenario: 'Credenciais inseridas provisoriamente durante depuração acabam salvas no repositório, permitindo login direto em painéis ou bancos.',
    blastRadius: 'Acesso não autorizado às contas ou serviços afetados, com possibilidade de movimentação lateral no ambiente interno.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Alterar a Senha em Todos os Serviços Associados',
        description: 'Mude a senha da conta de usuário, serviço ou integração imediatamente.',
        commandOrSnippet: 'openssl rand -base64 32 # Gere senhas de alta entropia com caracteres diversos',
        commandType: 'bash',
        keyTakeaway: 'Não reutilize a mesma senha em outros sistemas.'
      },
      {
        stepNumber: 2,
        title: 'Remover Fallbacks Inseguros do Código',
        description: 'Elimine construções do tipo process.env.PASS || "senha_default". A falta da variável deve causar erro fatal de inicialização.',
        commandOrSnippet: `const password = process.env.SERVICE_PASSWORD;\nif (!password) throw new Error("SERVICE_PASSWORD não foi definido!");`,
        commandType: 'typescript',
        keyTakeaway: 'Fallbacks com senhas padrões em código são uma das causas mais comuns de invasão.'
      },
      {
        stepNumber: 3,
        title: 'Implementar Cofre de Segredos ou .env.local',
        description: 'Em desenvolvimento local, utilize .env.local. Em produção, use AWS Secrets Manager, GCP Secret Manager ou Doppler.',
        commandOrSnippet: '# No arquivo .env.local (nunca comitar):\nSERVICE_PASSWORD=SenhaSeguraDoSeuAmbienteLocal',
        commandType: 'env',
        keyTakeaway: 'Garanta que o arquivo .env.example contenha apenas os nomes das variáveis sem valores reais.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Senha com fallback inseguro no código\nconst config = {\n  username: "admin",\n  password: process.env.ADMIN_PWD || "<SENHA_PADRAO_INSEGURA_EXEMPLO>"\n};`,
      after: `// ✅ SEGURO: Inicialização mandatória via variável protegida sem default\nconst password = process.env.ADMIN_PWD;\nif (!password) {\n  throw new Error("Variável ADMIN_PWD mandatória ausente na inicialização.");\n}\nconst config = { username: process.env.ADMIN_USER || "admin", password };`,
      explanation: 'O serviço deve falhar ao iniciar caso variáveis essenciais de segurança estejam ausentes.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "SENHA_VAZADA==>[REDACTED_PASSWORD]")',
      warning: 'Troque a senha no serviço real antes de purgar os commits do Git.'
    },
    secretRotationGuide: 'Altere a senha no serviço de autenticação ou banco e reinicie a aplicação com a nova variável.',
    preventativeMeasures: [
      'Adicione linters com regras contra literais em variáveis chamadas password/secret.',
      'Utilize gerenciadores de senhas corporativos para geração de senhas aleatórias de 32+ caracteres.'
    ],
    tags: ['password', 'credentials', 'plaintext', 'security', 'auth']
  },
  {
    id: 'api-key-openai',
    title: 'Chaves de API OpenAI & LLMs Generativos (sk-proj- / sk-live-)',
    category: 'API_KEY',
    applicableRuleIds: ['sec-openai-key'],
    severity: 'CRITICAL',
    cvssScore: 9.3,
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
    summary: 'Chaves da OpenAI com formato sk-proj-... ou sk-... permitem consumo irrestrito de modelos GPT-4, embeddings e fine-tunes na sua conta.',
    threatScenario: 'Atacantes utilizam sua chave para alimentar bots em massa ou revender acesso a LLMs, gerando faturas de milhares de dólares em poucas horas.',
    blastRadius: 'Prejuízo financeiro direto no cartão de crédito cadastrado na OpenAI e exaustão de cotas de IA da empresa.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Revogar a Chave no Dashboard OpenAI',
        description: 'Acesse platform.openai.com/api-keys e clique no ícone de lixeira ao lado da chave comprometida.',
        commandOrSnippet: 'https://platform.openai.com/api-keys',
        commandType: 'none',
        keyTakeaway: 'A revogação de chaves na OpenAI é quase instantânea.'
      },
      {
        stepNumber: 2,
        title: 'Configurar Limites de Gastos (Usage Limits)',
        description: 'Vá em Settings > Billing > Usage limits. Defina limites mensais rígidos (Soft limit e Hard limit) para evitar cobranças astronômicas em caso de novo vazamento.',
        commandOrSnippet: '# Exemplo: Hard limit de $50/mês para desenvolvimento',
        commandType: 'none',
        keyTakeaway: 'O Hard limit bloqueia qualquer nova chamada assim que o teto for atingido.'
      },
      {
        stepNumber: 3,
        title: 'Mover Chamadas de IA para o Backend com Cache',
        description: 'Nunca invoque new OpenAI({ apiKey, dangerouslyAllowBrowser: true }). Crie rotas de backend com rate-limiting e cache.',
        commandOrSnippet: `// server/routes/chat.ts\nimport OpenAI from 'openai';\nconst openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });`,
        commandType: 'typescript',
        keyTakeaway: 'Rotas de backend permitem validar tokens de usuários antes de consumir créditos da OpenAI.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Chave da OpenAI no frontend permitindo bypass no browser\nimport OpenAI from 'openai';\nconst client = new OpenAI({\n  apiKey: 'sk-proj-' + '<SUA_CHAVE_OPENAI_AQUI>',\n  dangerouslyAllowBrowser: true // ⚠️ NUNCA USE EM PRODUÇÃO\n});`,
      after: `// ✅ SEGURO: Frontend consome rota interna com controle de acesso\nconst res = await fetch('/api/chat', {\n  method: 'POST',\n  headers: { 'Content-Type': 'application/json' },\n  body: JSON.stringify({ message: promptText })\n});`,
      explanation: 'A opção dangerouslyAllowBrowser expõe sua chave diretamente no código JS enviado ao navegador do usuário.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "CHAVE_OPENAI_VAZADA==>[REDACTED_OPENAI_KEY]")',
      warning: 'Gere uma nova chave com permissões restritas antes de reescrever o git.'
    },
    secretRotationGuide: 'OpenAI Platform > API Keys > Create new secret key. Defina permissões de Read/Write apenas nos modelos necessários.',
    preventativeMeasures: [
      'Ative alertas de faturamento e limites diários de consumo no portal da OpenAI.',
      'Utilize gateways de IA intermediários com auditoria de prompts e rate-limiting por usuário.'
    ],
    tags: ['openai', 'gpt', 'llm', 'ai', 'apikey', 'chatgpt']
  },
  {
    id: 'api-path-sensitive',
    title: 'Rotas e Endpoints Administrativos ou Internos Expostos (/admin, /debug)',
    category: 'API_PATH',
    applicableRuleIds: ['sec-sensitive-api-path'],
    severity: 'MEDIUM',
    cvssScore: 7.5,
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
    summary: 'Caminhos como /api/admin/*, /internal/debug ou /actuator/metrics mapeados no código frontend revelam a topologia interna da API.',
    threatScenario: 'O atacante lê o bundle JavaScript e encontra endpoints não documentados para testar vulnerabilidades de IDOR/BOLA ou obter dados confidenciais sem autenticação.',
    blastRadius: 'Exposição de endpoints operacionais sensíveis, dados analíticos internos e aumento da superfície de ataque.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Aplicar Middleware de Autorização RBAC em Todas as Rotas',
        description: 'Garanta que cada endpoint administrativo verifique explicitamente os papéis (roles) do usuário antes de processar qualquer dado.',
        commandOrSnippet: `router.use('/admin', authenticateJwt, requireRole(['ADMIN', 'SECURITY_OFFICER']));`,
        commandType: 'typescript',
        keyTakeaway: 'Não confie na ocultação de links no frontend: o backend deve ser a autoridade absoluta de segurança.'
      },
      {
        stepNumber: 2,
        title: 'Bloquear Endpoints Internos no Reverse Proxy / Gateway',
        description: 'No Nginx, Cloudflare ou API Gateway, bloqueie o acesso público a caminhos como /debug/*, /actuator/* ou /metrics.',
        commandOrSnippet: `location /api/v1/internal/ {\n  allow 10.0.0.0/8; # Rede interna\n  deny all;        # Bloqueia internet pública\n}`,
        commandType: 'none',
        keyTakeaway: 'Rotas de diagnóstico técnico e métricas devem ser acessíveis apenas via VPN ou rede interna da VPC.'
      },
      {
        stepNumber: 3,
        title: 'Separar o Bundle de Clientes Comuns do Bundle de Administradores',
        description: 'Não compile componentes do painel administrativo no mesmo bundle JS servido aos usuários finais da aplicação.',
        commandOrSnippet: `// Utilize Dynamic Imports / Code Splitting:\nconst AdminPanel = React.lazy(() => import('./admin/AdminPanel'));`,
        commandType: 'typescript',
        keyTakeaway: 'Code splitting impede que usuários comuns baixem URLs e lógicas administrativas em seus navegadores.'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: Chamada direta para rota administrativa em script de cliente comum\nconst exportAllUsers = () => fetch('/api/v1/admin/users/export');`,
      after: `// ✅ SEGURO: Rota administrativa com validação rigorosa de sessão e token RBAC\nconst exportUsers = async () => {\n  const token = await getAdminToken();\n  return fetch('/api/v1/admin/users/export', {\n    headers: { Authorization: \`Bearer \${token}\` }\n  });\n};`,
      explanation: 'Garanta que todas as rotas administrativas exijam token JWT válido e papel administrativo no servidor.'
    },
    gitHistoryPurge: {
      command: '# Não requer expurgo de histórico se não envolver senhas, apenas refatoração das rotas.',
      warning: 'Verifique se nenhuma rota exposta contém tokens nos parâmetros de query string (?token=...).'
    },
    secretRotationGuide: 'Não se aplica a rotas estáticas; revise as permissões de acesso e firewalls.',
    preventativeMeasures: [
      'Adote o modelo Zero Trust com autenticação contínua em cada serviço.',
      'Realize testes de Broken Object Level Authorization (BOLA) regularmente com ferramentas SAST e DAST.'
    ],
    tags: ['api-path', 'endpoints', 'rbac', 'admin', 'routes', 'idor']
  },
  {
    id: 'high-entropy-secrets',
    title: 'Strings de Alta Entropia de Shannon (Tokens e Segredos Genéricos)',
    category: 'ENTROPY',
    applicableRuleIds: ['CUSTOM_REGEX', 'HIGH_ENTROPY'],
    severity: 'HIGH',
    cvssScore: 8.2,
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
    summary: 'Sequências aleatórias com entropia superior a 3.5 bits/caractere geralmente representam chaves de criptografia, tokens de sessão ou senhas de integração.',
    threatScenario: 'O atacante identifica o token pseudoaleatório e descobre que ele concede acesso a microsserviços internos, assinaturas de cookies ou webhooks corporativos.',
    blastRadius: 'Varia conforme o segredo identificado; pode comprometer a criptografia simétrica (AES/DES) ou integridade de cookies.',
    stepByStepPatching: [
      {
        stepNumber: 1,
        title: 'Identificar a Finalidade da String Detectada',
        description: 'Descubra qual módulo gera ou consome a string (ex.: sal de hash, chave HMAC, token de webhook ou segredo de sessão).',
        commandOrSnippet: 'git grep "string_detectada" # Localize todas as referências no repositório',
        commandType: 'bash',
        keyTakeaway: 'Compreenda se a string é realmente um segredo ou um hash estático/ID irrelevante (falso positivo).'
      },
      {
        stepNumber: 2,
        title: 'Mover para Variável de Ambiente com Nome Descritivo',
        description: 'Atribua um nome claro à variável no arquivo .env e remova a string literal do código.',
        commandOrSnippet: `INTERNAL_API_SECRET=token_aleatorio_detectado_aqui`,
        commandType: 'env',
        keyTakeaway: 'Nomes descritivos facilitam a gestão de segredos no cofre e evitam duplicações.'
      },
      {
        stepNumber: 3,
        title: 'Rotacionar o Segredo se Houve Exposição em Repositório Público',
        description: 'Gere uma nova string de 32+ bytes e atualize todos os consumidores do segredo.',
        commandOrSnippet: 'node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
        commandType: 'bash',
        keyTakeaway: 'Utilize geradores criptograficamente seguros (CSPRNG).'
      }
    ],
    beforeAfterCode: {
      language: 'typescript',
      before: `// ❌ INSEGURO: String de alta entropia fixada diretamente no código\nconst ENCRYPTION_KEY = "<CHAVE_CRIPTO_HEX_64_CHARS>";`,
      after: `// ✅ SEGURO: Chave carregada de variável de ambiente protegida\nconst encryptionKey = process.env.APP_ENCRYPTION_KEY;\nif (!encryptionKey) throw new Error("APP_ENCRYPTION_KEY is required");`,
      explanation: 'Chaves de criptografia simétrica nunca devem ser versionadas em código.'
    },
    gitHistoryPurge: {
      command: 'git filter-repo --replace-text <(echo "string_detectada==>[REDACTED_ENTROPY_STRING]")',
      warning: 'Valide se a string não é um hash estático inofensivo antes de executar a limpeza de histórico.'
    },
    secretRotationGuide: 'Gere nova sequência com crypto.randomBytes(32) e propague aos microsserviços dependentes.',
    preventativeMeasures: [
      'Ajuste o teto de entropia no SecScan CLI (--min-entropy 3.5) para evitar falsos positivos.',
      'Formalize regras customizadas no SecScan para padrões específicos da sua empresa.'
    ],
    tags: ['entropy', 'shannon', 'random', 'secret', 'tokens', 'crypto']
  }
];

/**
 * Maps any scan finding to the most specific remediation wiki guide
 */
export function getRemediationGuideForFinding(finding: ScanFinding): RemediationWikiGuide {
  const ruleId = (finding.ruleId || '').toLowerCase();
  const ruleName = (finding.ruleName || '').toLowerCase();
  const category = finding.category;
  const matched = (finding.matchedSecret || '').toLowerCase();

  // 1. Direct rule ID match
  const byRuleId = REMEDIATION_WIKI_GUIDES.find(g => 
    g.applicableRuleIds.some(r => r.toLowerCase() === ruleId)
  );
  if (byRuleId) return byRuleId;

  // 2. Pattern heuristics by ruleName and content
  if (ruleName.includes('aws') || ruleId.includes('aws') || matched.startsWith('akia')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'cloud-credentials-aws')!;
  }

  if (ruleName.includes('google') || ruleName.includes('gemini') || matched.startsWith('aiza')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'cloud-credentials-gcp')!;
  }

  if (ruleName.includes('github') || ruleId.includes('github') || matched.startsWith('ghp_')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'auth-token-github')!;
  }

  if (ruleName.includes('stripe') || ruleId.includes('stripe') || matched.startsWith('sk_live_') || matched.startsWith('rk_live_')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'api-key-stripe')!;
  }

  if (ruleName.includes('openai') || ruleId.includes('openai') || matched.startsWith('sk-proj-') || matched.startsWith('sk-')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'api-key-openai')!;
  }

  if (ruleName.includes('jwt') || ruleId.includes('jwt') || matched.startsWith('eyj')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'auth-token-jwt')!;
  }

  if (ruleName.includes('postgres') || ruleName.includes('mongo') || ruleName.includes('mysql') || ruleName.includes('redis') || ruleId.includes('db-uri')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'database-uri-all')!;
  }

  if (ruleName.includes('private key') || ruleName.includes('rsa') || ruleName.includes('ssh') || ruleId.includes('private-key')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'private-key-crypto')!;
  }

  if (ruleName.includes('password') || ruleName.includes('senha') || ruleId.includes('hardcoded-pass')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'password-hardcoded')!;
  }

  if (category === 'API_PATH' || ruleName.includes('route') || ruleName.includes('endpoint')) {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'api-path-sensitive')!;
  }

  // 3. Category Fallback
  if (category === 'CLOUD_CREDENTIAL') {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'cloud-credentials-aws')!;
  }
  if (category === 'DATABASE_URI') {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'database-uri-all')!;
  }
  if (category === 'PRIVATE_KEY') {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'private-key-crypto')!;
  }
  if (category === 'AUTH_TOKEN') {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'auth-token-jwt')!;
  }
  if (category === 'API_KEY') {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'api-key-stripe')!;
  }
  if (category === 'PASSWORD') {
    return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'password-hardcoded')!;
  }

  // Fallback to high entropy
  return REMEDIATION_WIKI_GUIDES.find(g => g.id === 'high-entropy-secrets') || REMEDIATION_WIKI_GUIDES[0];
}
