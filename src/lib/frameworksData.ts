import {
  MitreAttackTechnique,
  MitreD3fendCountermeasure,
  NistCsfSubcategory,
  OwaspWstgTestCase,
  ScanFinding,
  NistAuditStatus,
  WstgTestStatus
} from '../types';

// ============================================================================
// 1. MITRE ATT&CK & D3FEND MAPPINGS
// ============================================================================

export const MITRE_ATTACK_TECHNIQUES: MitreAttackTechnique[] = [
  {
    id: 'T1552.001',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    name: 'Credentials In Files',
    description:
      'Adversários procuram por arquivos locais de código, scripts de configuração (.env, application.yml, config.json) e repositórios de controle de versão que contenham senhas em texto puro, tokens de API de nuvem ou chaves privadas.',
    adversaryObjective:
      'Descobrir e extrair credenciais administrativas ou de serviços diretamente de arquivos no sistema de arquivos ou repositórios.',
    matchedKeywords: ['aws', 'token', 'secret', 'key', 'password', 'api', 'env', 'cred', 'credentials', 'bearer', 'private_key', 'ssh'],
    docUrl: 'https://attack.mitre.org/techniques/T1552/001/',
    d3fendCountermeasures: [
      {
        id: 'D3-SCRA',
        name: 'Secret Credential Revocation & Auditing',
        category: 'Evict',
        description: 'Revogar imediatamente credenciais vazadas e auditar logs de chamadas nas APIs para identificar acessos não autorizados.',
        implementationGuide: 'Execute a rotação imediata no IAM/Cloud Provider, invalide o segredo comprometido e use GitGuardian/TruffleHog em pré-commit hooks.',
        verificationMethod: 'Verifique se a credencial revogada retorna HTTP 401 Unauthorized e se não há cópias em commits anteriores.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:CredentialRevocation/'
      },
      {
        id: 'D3-EAM',
        name: 'Encrypted Authentication Material (Vault / KMS)',
        category: 'Harden',
        description: 'Armazenar todo material de autenticação em cofres criptografados (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault) em vez de arquivos planos.',
        implementationGuide: 'Injete variáveis via runtime seguro (IAM Roles, Workload Identity) sem expor strings literais em código.',
        verificationMethod: 'Auditar arquivos rastreados no Git com regex e scanners estáticos para confirmar ausência de strings de alta entropia.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:EncryptedAuthenticationMaterial/'
      },
      {
        id: 'D3-SP',
        name: 'Static Program Analysis (Secret SAST)',
        category: 'Detect',
        description: 'Analisar o código fonte antes do commit para detectar assinaturas regex e entropia compatível com segredos.',
        implementationGuide: 'Integrar scanners estáticos (SecScan CI/CD, Git Pre-Commit Hooks, GitHub Actions Security Gate).',
        verificationMethod: 'Garantir que qualquer Pull Request com segredo falhe na esteira CI com Exit Code 1.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:StaticProgramAnalysis/'
      }
    ]
  },
  {
    id: 'T1528',
    tacticId: 'TA0006',
    tacticName: 'Credential Access',
    name: 'Steal Application Access Token',
    description:
      'Adversários podem capturar tokens de acesso OAuth2, JWTs ou tokens de serviço expostos em bundles JavaScript de frontend ou código cliente.',
    adversaryObjective:
      'Reutilizar tokens de curta ou longa duração para personificar a aplicação perante APIs terceiras (Slack, GitHub, Stripe, OpenAI).',
    matchedKeywords: ['jwt', 'bearer', 'oauth', 'token', 'slack', 'github_token', 'stripe', 'openai', 'apikey'],
    docUrl: 'https://attack.mitre.org/techniques/T1528/',
    d3fendCountermeasures: [
      {
        id: 'D3-CH',
        name: 'Credential Hardening & Ephemeral Tokens',
        category: 'Harden',
        description: 'Utilizar tokens efêmeros com TTL estrito (≤ 15 minutos) e escopo de permissão mínimo (Princípio do Menor Privilégio).',
        implementationGuide: 'Configure rotação de sessão e tokens assinados com chaves assimétricas RS256/ES256 com verificação de emissor (iss) e audiência (aud).',
        verificationMethod: 'Testar expiração de token e rejeição de assinaturas forjadas (alg=none test).',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:CredentialHardening/'
      },
      {
        id: 'D3-BAP',
        name: 'Backend-for-Frontend (BFF) Token Isolation',
        category: 'Isolate',
        description: 'Nunca expor tokens mestres no navegador; utilizar proxies de backend para realizar chamadas autenticadas.',
        implementationGuide: 'Rotear requisições sensíveis através de endpoints internos (/api/*) que injetam as credenciais no lado do servidor.',
        verificationMethod: 'Inspecione pacotes e bundles .js compilados para garantir zero referências a chaves privadas.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:ProcessIsolation/'
      }
    ]
  },
  {
    id: 'T1078',
    tacticId: 'TA0001',
    tacticName: 'Initial Access',
    name: 'Valid Accounts',
    description:
      'Adversários obtêm e abusam de credenciais existentes de contas legítimas para obter acesso inicial, contornando a maioria dos controles perimetrais.',
    adversaryObjective:
      'Logar em painéis administrativos, bancos de dados em nuvem ou serviços de infraestrutura sem disparar alarmes de invasão evidente.',
    matchedKeywords: ['admin', 'root', 'user', 'password', 'login', 'credentials', 'database', 'postgres', 'mongo', 'mysql'],
    docUrl: 'https://attack.mitre.org/techniques/T1078/',
    d3fendCountermeasures: [
      {
        id: 'D3-MFA',
        name: 'Multi-Factor Authentication (MFA)',
        category: 'Harden',
        description: 'Exigir múltiplos fatores de autenticação independentes para todos os acessos humanos e privilegiados.',
        implementationGuide: 'Ativar FIDO2/WebAuthn ou TOTP corporativo obrigatório para todos os administradores e consoles de nuvem.',
        verificationMethod: 'Tentar autenticação apenas com senha e confirmar bloqueio estrito de acesso sem o segundo fator.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:MultiFactorAuthentication/'
      },
      {
        id: 'D3-URA',
        name: 'User and Role Auditing (RBAC/ABAC)',
        category: 'Model',
        description: 'Auditar periodicamente permissões de contas e revogar credenciais antigas ou com permissões excessivas.',
        implementationGuide: 'Implementar revisões de acesso trimestrais e desativação automática de contas inativas (> 30 dias).',
        verificationMethod: 'Verificar relatórios de IAM com acessos não utilizados e políticas de permissão "AdministratorAccess".',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:UserAccountAnalysis/'
      }
    ]
  },
  {
    id: 'T1059',
    tacticId: 'TA0002',
    tacticName: 'Execution',
    name: 'Command and Scripting Interpreter',
    description:
      'Adversários podem abusar de interpretadores de comandos (bash, powershell, sh, python, node eval) para executar código malicioso.',
    adversaryObjective:
      'Executar comandos arbitrários no sistema operacional host através de sinks de injeção no código.',
    matchedKeywords: ['exec', 'eval', 'spawn', 'child_process', 'system', 'popen', 'shell', 'bash'],
    docUrl: 'https://attack.mitre.org/techniques/T1059/',
    d3fendCountermeasures: [
      {
        id: 'D3-EDR',
        name: 'Process Execution Auditing',
        category: 'Detect',
        description: 'Monitorar a criação de subprocessos incomuns gerados pelo processo do servidor web ou aplicação.',
        implementationGuide: 'Configurar auditd, Falco ou EDR para alertar processos gerados por nós filhos de node/python/java.',
        verificationMethod: 'Testar comando benigno em laboratório e validar emissão de evento de telemetria.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/'
      },
      {
        id: 'D3-IV',
        name: 'Input Validation & Parameterized Execution',
        category: 'Harden',
        description: 'Nunca concatenar entradas de usuário em chamadas de shell; utilizar arrays de argumentos com APIs nativas seguras.',
        implementationGuide: 'Substitua child_process.exec() por execFile() com argumentos parametrizados estritamente validados por allowlist.',
        verificationMethod: 'Fazer testes de injeção de payload (; ls, | id) e verificar ausência de quebra de fluxo.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:InputValidation/'
      }
    ]
  },
  {
    id: 'T1087',
    tacticId: 'TA0007',
    tacticName: 'Discovery',
    name: 'Account Discovery',
    description:
      'Adversários podem enumerar nomes de usuários, papéis e contas de serviço através de mensagens de erro detalhadas ou endpoints de API expostos.',
    adversaryObjective:
      'Mapear identidades corporativas e privilégios para planejar ataques direcionados de força bruta ou spear phishing.',
    matchedKeywords: ['users', 'accounts', 'api/users', 'auth/users', 'graphql', 'enum'],
    docUrl: 'https://attack.mitre.org/techniques/T1087/',
    d3fendCountermeasures: [
      {
        id: 'D3-RL',
        name: 'API Rate Limiting & Anti-Enumeration',
        category: 'Harden',
        description: 'Implementar limites estritos de requisições por IP/token e respostas uniformes para falhas de login/recuperação de senha.',
        implementationGuide: 'Configure express-rate-limit ou regras no Cloudflare/AWS WAF para endpoints de autenticação.',
        verificationMethod: 'Disparar 50 requisições seguidas e validar retorno HTTP 429 Too Many Requests.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:NetworkTrafficThrottling/'
      }
    ]
  },
  {
    id: 'T1005',
    tacticId: 'TA0009',
    tacticName: 'Collection',
    name: 'Data from Local System',
    description:
      'Adversários buscam arquivos locais contendo dados corporativos confidenciais, backups de banco de dados (.sql, .dump), chaves privadas e relatórios.',
    adversaryObjective:
      'Coletar dados de alto valor armazenados em texto claro antes de proceder com a exfiltração.',
    matchedKeywords: ['backup', 'dump', 'sql', 'database', 'customers', 'pII', 'card', 'cpf'],
    docUrl: 'https://attack.mitre.org/techniques/T1005/',
    d3fendCountermeasures: [
      {
        id: 'D3-FBR',
        name: 'File Access Restriction & Integrity Monitoring',
        category: 'Isolate',
        description: 'Restringir permissões de leitura do sistema de arquivos para o usuário de execução do serviço (chmod 600 em confs).',
        implementationGuide: 'Execute contêineres como usuário não-root com sistema de arquivos raiz somente-leitura (read-only rootfs).',
        verificationMethod: 'Verificar com "id" dentro do container que UID != 0 e que gravação em / é rejeitada.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:FileAccessPatternAnalysis/'
      }
    ]
  },
  {
    id: 'T1567',
    tacticId: 'TA0010',
    tacticName: 'Exfiltration',
    name: 'Exfiltration Over Web Service',
    description:
      'Adversários podem usar canais legítimos (serviços de webhook, repositórios públicos, servidores webhook.site, discord webhooks) para transferir dados roubados para fora da rede.',
    adversaryObjective:
      'Contornar firewalls corporativos utilizando protocolos HTTPS padrão e domínios com reputação favorável.',
    matchedKeywords: ['webhook', 'discord.com', 'slack.com', 'pastebin', 'transfer.sh', 'requestbin'],
    docUrl: 'https://attack.mitre.org/techniques/T1567/',
    d3fendCountermeasures: [
      {
        id: 'D3-EGF',
        name: 'Egress Traffic Filtering & DNS Inspection',
        category: 'Detect',
        description: 'Bloquear tráfego de saída não autorizado dos clusters de produção e inspecionar consultas DNS para domínios anômalos.',
        implementationGuide: 'Aplique NetworkPolicies no Kubernetes restringindo conexões externas apenas a gateways autorizados.',
        verificationMethod: 'Tentar curl para serviço externo não catalogado a partir do pod de produção e validar timeout/rejeição.',
        docUrl: 'https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/'
      }
    ]
  }
];

// ============================================================================
// 2. NIST CYBERSECURITY FRAMEWORK (CSF 2.0)
// ============================================================================

export const NIST_CSF_SUBCATEGORIES: NistCsfSubcategory[] = [
  // --- GOVERN (GV) ---
  {
    id: 'GV.OC-01',
    functionId: 'GV',
    functionName: 'Govern (Governança)',
    categoryName: 'Organizational Context',
    title: 'Missão e Requisitos Legais de Segurança da Informação',
    requirement:
      'A missão da organização, seus objetivos e os requisitos legais, regulatórios (LGPD, GDPR) e contratuais relativos à segurança cibernética são compreendidos e documentados.',
    devSecOpsAction:
      'Definir políticas corporativas claras de gestão de credenciais e tolerância zero a segredos em código.',
    verificationEvidence: 'Política de Desenvolvimento Seguro (SDLC) aprovada e revisada anualmente.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },
  {
    id: 'GV.SC-04',
    functionId: 'GV',
    functionName: 'Govern (Governança)',
    categoryName: 'Cybersecurity Supply Chain',
    title: 'Gestão de Riscos na Cadeia de Suprimentos (Supply Chain)',
    requirement:
      'Fornecedores, dependências de código aberto (npm, pypi) e parceiros de nuvem são avaliados quanto a riscos de segurança e conformidade.',
    devSecOpsAction:
      'Executar npm audit e verificação de Software Bill of Materials (SBOM) no pipeline CI/CD.',
    verificationEvidence: 'Relatório de escaneamento de dependências integrado com bloqueio de vulnerabilidades críticas.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },

  // --- IDENTIFY (ID) ---
  {
    id: 'ID.AM-01',
    functionId: 'ID',
    functionName: 'Identify (Identificação)',
    categoryName: 'Asset Management',
    title: 'Inventário de Ativos de Software e Repositórios',
    requirement:
      'Repositórios de código, artefatos compilados, endpoints de API e bancos de dados são catalogados e mantidos em inventário contínuo.',
    devSecOpsAction:
      'Utilizar o LinkFinder e catalogador de repositórios do SecScan para manter rastreabilidade total de endpoints expostos.',
    verificationEvidence: 'Lista atualizada de endpoints de API e repositórios monitorados.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },
  {
    id: 'ID.RA-01',
    functionId: 'ID',
    functionName: 'Identify (Identificação)',
    categoryName: 'Risk Assessment',
    title: 'Identificação Contínua de Vulnerabilidades e Segredos',
    requirement:
      'Vulnerabilidades em ativos de software e credenciais expostas são identificadas, documentadas e correlacionadas com fontes de ameaça.',
    devSecOpsAction:
      'Executar varredura automática (SecScan) a cada alteração de código ou commit.',
    verificationEvidence: 'Histórico de varreduras com matriz de risco e achados categorizados por severidade.',
    docUrl: 'https://www.nist.gov/cyberframework',
    autoCheckKeywords: ['secret', 'vulnerability', 'cwe', 'entropy']
  },

  // --- PROTECT (PR) ---
  {
    id: 'PR.AA-01',
    functionId: 'PR',
    functionName: 'Protect (Proteção)',
    categoryName: 'Identity & Access Management',
    title: 'Gestão de Credenciais e Autenticação Segura',
    requirement:
      'Identidades e credenciais são emitidas, gerenciadas, rotacionadas e revogadas com base no princípio do menor privilégio.',
    devSecOpsAction:
      'Substituir senhas e chaves estáticas por variáveis de ambiente, IAM Roles ou Vault com rotação automática.',
    verificationEvidence: 'Zero credenciais críticas ativas em arquivos planos no repositório.',
    docUrl: 'https://www.nist.gov/cyberframework',
    autoCheckKeywords: ['password', 'secret', 'key', 'aws', 'token']
  },
  {
    id: 'PR.DS-01',
    functionId: 'PR',
    functionName: 'Protect (Proteção)',
    categoryName: 'Data Security',
    title: 'Proteção de Dados em Repouso e em Trânsito',
    requirement:
      'Dados confidenciais, chaves criptográficas e informações de autenticação são protegidos por criptografia forte.',
    devSecOpsAction:
      'Garantir que endpoints de API usem HTTPS/TLS 1.3 e que chaves mestras utilizem algoritmos robustos (AES-256, RSA-4096).',
    verificationEvidence: 'Certificados TLS válidos e ausência de endpoints em HTTP inseguro.',
    docUrl: 'https://www.nist.gov/cyberframework',
    autoCheckKeywords: ['http://', 'crypto', 'rsa', 'private_key']
  },
  {
    id: 'PR.PS-01',
    functionId: 'PR',
    functionName: 'Protect (Proteção)',
    categoryName: 'Platform Security',
    title: 'Configurações de Segurança e Linhas de Base (Baselines)',
    requirement:
      'Configurações de ambiente, arquivos de implantação e parâmetros de contêineres seguem padrões rígidos de hardening.',
    devSecOpsAction:
      'Aplicar regras de lint de segurança e ignorar arquivos sensíveis (.env, .pem, id_rsa) no .gitignore global.',
    verificationEvidence: '.gitignore configurado e regras de qualidade ativas no Quality Gate.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },

  // --- DETECT (DE) ---
  {
    id: 'DE.CM-01',
    functionId: 'DE',
    functionName: 'Detect (Detecção)',
    categoryName: 'Continuous Monitoring',
    title: 'Monitoramento Contínuo e Análise Estática de Código (SAST)',
    requirement:
      'A base de código e os ambientes de desenvolvimento são monitorados continuamente para detectar introdução de segredos e vulnerabilidades.',
    devSecOpsAction:
      'Integrar SecScan no pipeline de CI/CD com limite de Quality Gate e alertas imediatos.',
    verificationEvidence: 'Workflows do GitHub Actions configurados com exit code 1 para quebra de build.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },
  {
    id: 'DE.AE-02',
    functionId: 'DE',
    functionName: 'Detect (Detecção)',
    categoryName: 'Adverse Event Analysis',
    title: 'Análise de Eventos Anômalos e Incidentes em Potencial',
    requirement:
      'Eventos detectados são analisados para compreender o impacto e a intenção de possíveis invasões.',
    devSecOpsAction:
      'Consultar o Risk Trend Chart e o MTTR Mini Trendline para avaliar desvios na postura de segurança.',
    verificationEvidence: 'Registros de auditoria e trilha histórica de varreduras gravada no workspace.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },

  // --- RESPOND (RS) ---
  {
    id: 'RS.MA-01',
    functionId: 'RS',
    functionName: 'Respond (Resposta)',
    categoryName: 'Incident Management',
    title: 'Execução do Plano de Resposta a Incidentes de Segurança',
    requirement:
      'Planos de resposta a vazamentos de credenciais são acionados prontamente após a confirmação do alerta.',
    devSecOpsAction:
      'Seguir os playbooks da Remediation Wiki do SecScan para revogação, auditoria de logs e rotação.',
    verificationEvidence: 'Playbooks de remediação documentados por fornecedor (AWS, GitHub, Slack, Stripe).',
    docUrl: 'https://www.nist.gov/cyberframework'
  },
  {
    id: 'RS.MI-01',
    functionId: 'RS',
    functionName: 'Respond (Resposta)',
    categoryName: 'Mitigation',
    title: 'Mitigação Imediata e Contenção de Credenciais Comprometidas',
    requirement:
      'Ações são realizadas para conter o impacto de incidentes e mitigar a exposição de chaves e segredos.',
    devSecOpsAction:
      'Utilizar a ferramenta de Correção Sugerida (SuggestedFix) para sanitizar o código e invalidar chaves expostas.',
    verificationEvidence: 'Tempo Médio de Remediação (MTTR) dentro da meta de SLA estabelecida.',
    docUrl: 'https://www.nist.gov/cyberframework'
  },

  // --- RECOVER (RC) ---
  {
    id: 'RC.RP-01',
    functionId: 'RC',
    functionName: 'Recover (Recuperação)',
    categoryName: 'Recovery Planning',
    title: 'Restauração da Postura de Segurança e Lições Aprendidas',
    requirement:
      'Processos de recuperação são executados e lições aprendidas são incorporadas às novas regras e políticas preventivas.',
    devSecOpsAction:
      'Criar novas regras de Regex no SecScan para evitar que padrões semelhantes voltem a ser inseridos.',
    verificationEvidence: 'Banco de regras customizadas atualizado com novos padrões regex pós-incidente.',
    docUrl: 'https://www.nist.gov/cyberframework'
  }
];

// ============================================================================
// 3. OWASP WEB SECURITY TESTING GUIDE (WSTG v4.2)
// ============================================================================

export const OWASP_WSTG_TEST_CASES: OwaspWstgTestCase[] = [
  {
    id: 'WSTG-INFO-05',
    categoryCode: 'INFO',
    categoryTitle: 'Coleta de Informações (Recon)',
    title: 'Revisão do Conteúdo Web para Vazamento de Informações',
    objective:
      'Inspecionar páginas web, bundles de JavaScript compilados e comentários em HTML para identificar segredos, credenciais de desenvolvimento, endpoints ocultos de API e tokens de autenticação.',
    methodology:
      '1. Analisar scripts .js carregados no frontend utilizando o minerador JS Miner do SecScan.\n2. Extrair caminhos de API internos com o LinkFinder.\n3. Verificar strings com alta entropia Shannon compatíveis com tokens de acesso.',
    cliVerification:
      'curl -s https://app.target.internal/main.bundle.js | grep -E "(api[_-]?key|bearer|secret|token)"',
    remediationAdvice:
      'Remover mapas de código-fonte (.map) em produção e jamais embutir credenciais secretas em código do cliente.',
    severity: 'HIGH',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage'
  },
  {
    id: 'WSTG-CONF-04',
    categoryCode: 'CONF',
    categoryTitle: 'Gerenciamento de Configuração',
    title: 'Revisão de Arquivos Antigos, de Backup e Não Referenciados',
    objective:
      'Identificar se arquivos sensíveis de backup (.bak, .old, .orig, .env.backup, config.php~) ou arquivos de configuração padrão estão acessíveis e contêm segredos.',
    methodology:
      '1. Escanear a árvore de arquivos do projeto em busca de extensões de risco.\n2. Inspecionar arquivos .env no repositório.\n3. Validar se o .gitignore cobre todas as variantes de arquivos temporários e chaves.',
    cliVerification:
      'find . -type f \\( -name "*.env*" -o -name "*.bak" -o -name "*~" -o -name "*.old" \\) ! -path "*/node_modules/*"',
    remediationAdvice:
      'Adicionar regras de exclusão rígidas no .gitignore e habilitar o Quality Gate no CI/CD para impedir commit de arquivos de configuração local.',
    severity: 'CRITICAL',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
  },
  {
    id: 'WSTG-ATHN-06',
    categoryCode: 'ATHN',
    categoryTitle: 'Testes de Autenticação',
    title: 'Teste para Senhas Fracas e Credenciais Hardcoded no Código',
    objective:
      'Descobrir senhas estáticas, chaves criptográficas pré-definidas ou senhas de contas de serviço fixadas diretamente no código-fonte.',
    methodology:
      '1. Rodar regex em busca de declarações como "password =", "client_secret:", "admin:admin".\n2. Analisar histórico do Git para commits que removeram credenciais mas mantiveram o segredo no log histórico.\n3. Validar entropia e padrões conhecidos de fabricantes (AWS, GitHub, Stripe).',
    cliVerification:
      'git log -p -S "password" -- "*.js" "*.ts" "*.json" "*.env"',
    remediationAdvice:
      'Injetar segredos por variáveis de ambiente ou secret stores gerenciados (KMS / HashiCorp Vault). Rotacionar qualquer segredo identificado.',
    severity: 'CRITICAL',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Weak_Password_Policy'
  },
  {
    id: 'WSTG-ATHZ-02',
    categoryCode: 'ATHZ',
    categoryTitle: 'Testes de Autorização',
    title: 'Teste de Contorno do Esquema de Autorização (BOLA / IDOR)',
    objective:
      'Verificar se endpoints de API recém-descobertos realizam verificações estritas de controle de acesso ao manipular identificadores de recursos (ex: /api/users/{id}).',
    methodology:
      '1. Coletar a lista completa de rotas via LinkFinder.\n2. Identificar parâmetros de rota que aceitam IDs de usuário ou recursos sensíveis.\n3. Testar requisições autenticadas como Usuário A tentando acessar recursos do Usuário B.',
    cliVerification:
      'curl -H "Authorization: Bearer $USER_A_TOKEN" https://app.target.internal/api/documents/102',
    remediationAdvice:
      'Implementar controle de acesso baseado em atributos (ABAC) com validação de propriedade do recurso no nível de domínio/banco.',
    severity: 'HIGH',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema'
  },
  {
    id: 'WSTG-CRYP-01',
    categoryCode: 'CRYP',
    categoryTitle: 'Testes Criptográficos',
    title: 'Teste para Segurança de Camada de Transporte Fraca (HTTP vs HTTPS)',
    objective:
      'Garantir que todas as comunicações de API e conexões entre microsserviços utilizem exclusivamente protocolos seguros com cifras criptográficas modernas.',
    methodology:
      '1. Auditar URLs geradas e hardcoded no código com o scanner de Endpoints.\n2. Identificar URLs iniciadas com "http://" em chamadas externas.\n3. Checar cabeçalhos HSTS (Strict-Transport-Security).',
    cliVerification:
      'curl -sI https://app.target.internal | grep -i "strict-transport-security"',
    remediationAdvice:
      'Forçar redirecionamento de HTTP para HTTPS (porta 443), habilitar HSTS com max-age mínimo de 31536000 e desabilitar TLS < 1.2.',
    severity: 'MEDIUM',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security'
  },
  {
    id: 'WSTG-CRYP-04',
    categoryCode: 'CRYP',
    categoryTitle: 'Testes Criptográficos',
    title: 'Teste para Criptografia Fraca e Chaves Criptográficas Hardcoded',
    objective:
      'Localizar chaves privadas RSA, certificados PEM, chaves simétricas AES ou salts de criptografia expostos no código-fonte.',
    methodology:
      '1. Buscar blocos "-----BEGIN (RSA )?PRIVATE KEY-----".\n2. Checar uso de algoritmos obsoletos como MD5 ou SHA-1 para assinaturas ou senhas.\n3. Avaliar geração de números aleatórios criptograficamente seguros (CSPRNG vs Math.random()).',
    cliVerification:
      'grep -rnE "-----BEGIN [A-Z ]*PRIVATE KEY-----" .',
    remediationAdvice:
      'Substituir Math.random() por crypto.randomBytes() ou Web Crypto API. Chaves assimétricas devem residir exclusivamente em HSM ou KMS seguro.',
    severity: 'CRITICAL',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/04-Testing_for_Weak_Encryption'
  },
  {
    id: 'WSTG-INPV-01',
    categoryCode: 'INPV',
    categoryTitle: 'Validação de Entradas & Injeção',
    title: 'Teste para Cross-Site Scripting Refletido (XSS)',
    objective:
      'Avaliar se dados controlados pelo usuário fluem sem sanitização até sinks de renderização HTML no frontend (ex: innerHTML, dangerouslySetInnerHTML).',
    methodology:
      '1. Inspecionar o grafo de fluxo de dados (DataFlowGraph) do SecScan para rastrear tainted sources até sinks.\n2. Testar payloads de escape de contexto.\n3. Checar cabeçalhos de Content-Security-Policy (CSP).',
    cliVerification:
      'curl -s "https://app.target.internal/search?q=<script>alert(1)</script>" | grep "<script>alert(1)</script>"',
    remediationAdvice:
      'Utilizar renderização reativa segura do framework (JSX / textContent), aplicar DOMPurify em HTML rico e configurar CSP robusta.',
    severity: 'HIGH',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting'
  },
  {
    id: 'WSTG-INPV-12',
    categoryCode: 'INPV',
    categoryTitle: 'Validação de Entradas & Injeção',
    title: 'Teste para Injeção de Comandos no Sistema Operacional (OS Command Injection)',
    objective:
      'Identificar pontos onde entradas externas são passadas para o shell do servidor sem sanitização ou uso de APIs parametrizadas.',
    methodology:
      '1. Localizar chamadas a child_process.exec(), system(), popen() no código com o inspetor de fluxo.\n2. Tentar injeção de operadores de shell (&, &&, |, ||, ;, `cmd`).',
    cliVerification:
      'curl -X POST -d "ip=127.0.0.1;id" https://app.target.internal/api/diagnostic/ping',
    remediationAdvice:
      'Evitar invocar o shell do SO. Quando inevitável, utilizar execFile() com argumentos estritamente tipados e validados por allowlist.',
    severity: 'CRITICAL',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection'
  },
  {
    id: 'WSTG-BUSL-02',
    categoryCode: 'BUSL',
    categoryTitle: 'Lógica de Negócios & Abuso',
    title: 'Teste de Defesas Contra Abuso da Aplicação e Força Bruta',
    objective:
      'Verificar se as rotas de API possuem mecanismos para mitigar ataques de enumeração massiva, scraping agressivo e exaustão de quota de tokens.',
    methodology:
      '1. Analisar presença de rate limiters nos endpoints de autenticação e busca.\n2. Testar envio de rajadas de requisições concorrentes.',
    cliVerification:
      'for i in {1..20}; do curl -s -o /dev/null -w "%{http_code}\n" https://app.target.internal/api/auth/login; done',
    remediationAdvice:
      'Configurar rate limiting em camadas (IP, Token, Usuário), CAPTCHA adaptativo e bloqueio temporário de requisições anômalas.',
    severity: 'MEDIUM',
    docUrl: 'https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests'
  }
];

// ============================================================================
// 4. CORRELATION & AUDIT HELPER FUNCTIONS
// ============================================================================

/**
 * Correlates scan findings to MITRE ATT&CK techniques based on rule name, description and secret keywords.
 */
export function correlateFindingsToMitre(findings: ScanFinding[]): {
  technique: MitreAttackTechnique;
  matchedFindings: ScanFinding[];
}[] {
  return MITRE_ATTACK_TECHNIQUES.map(tech => {
    const matched = findings.filter(f => {
      const targetText = `${f.ruleName || ''} ${f.description || ''} ${f.matchedSecret || ''} ${f.file || ''}`.toLowerCase();
      return tech.matchedKeywords.some(kw => targetText.includes(kw.toLowerCase()));
    });
    return {
      technique: tech,
      matchedFindings: matched
    };
  });
}

/**
 * Calculates auto-compliance status for NIST CSF subcategories based on real workspace findings.
 */
export function evaluateAutoNistStatus(
  sub: NistCsfSubcategory,
  findings: ScanFinding[],
  userSavedStatus?: NistAuditStatus
): {
  status: NistAuditStatus;
  violatingFindings: ScanFinding[];
  isAutoComputed: boolean;
} {
  if (userSavedStatus) {
    return {
      status: userSavedStatus,
      violatingFindings: [],
      isAutoComputed: false
    };
  }

  if (!sub.autoCheckKeywords || sub.autoCheckKeywords.length === 0) {
    return {
      status: 'UNDER_REVIEW',
      violatingFindings: [],
      isAutoComputed: true
    };
  }

  const violating = findings.filter(f => {
    const text = `${f.ruleName || ''} ${f.description || ''} ${f.matchedSecret || ''}`.toLowerCase();
    return sub.autoCheckKeywords!.some(kw => text.includes(kw.toLowerCase()));
  });

  if (violating.length === 0) {
    return {
      status: 'COMPLIANT',
      violatingFindings: [],
      isAutoComputed: true
    };
  }

  const hasCritical = violating.some(f => f.severity === 'CRITICAL');
  return {
    status: hasCritical ? 'NON_COMPLIANT' : 'PARTIAL',
    violatingFindings: violating,
    isAutoComputed: true
  };
}

/**
 * Correlates scan findings with OWASP WSTG test cases
 */
export function correlateFindingsToWstg(
  testCase: OwaspWstgTestCase,
  findings: ScanFinding[]
): ScanFinding[] {
  if (testCase.id === 'WSTG-ATHN-06') {
    return findings.filter(f => f.severity === 'CRITICAL' || /password|secret|key/i.test(f.ruleName));
  }
  if (testCase.id === 'WSTG-CONF-04') {
    return findings.filter(f => /\.env|config|\.bak|credentials/i.test(f.file));
  }
  if (testCase.id === 'WSTG-CRYP-04') {
    return findings.filter(f => /private_key|rsa|jwt|cert/i.test(f.ruleName));
  }
  if (testCase.id === 'WSTG-INFO-05') {
    return findings.filter(f => /token|api_key|bearer/i.test(f.ruleName));
  }
  return [];
}
