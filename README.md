# 🛡️ SecScan AppSec Suite - Advanced SAST, Secret Matrix, DataFlow & Quality Gate Platform

[![CI/CD Security Analysis](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?logo=github-actions&logoColor=white)](.github/workflows/ci-cd.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22%20LTS-339933?logo=nodedotjs&logoColor=white)](package.json)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Standard-4B32C3?logo=github&logoColor=white)](https://sarifweb.azurewebsites.net/)
[![OWASP & Snyk Verified](https://img.shields.io/badge/Advisories-OWASP%20%7C%20Snyk%20%7C%20CWE-00FF41)](https://owasp.org/)
[![Quality Gate](https://img.shields.io/badge/Quality%20Gate-Max%20Risk%20Score%20(0--100)-FF3E00)](README.md)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**SecScan AppSec Suite** é uma plataforma avançada e modular de **Análise Estática de Segurança de Aplicações (SAST)**, auditoria de código JavaScript/TypeScript, detecção de segredos de alta entropia e inteligência de superfície de ataque. Desenvolvida para engenheiros de DevSecOps, AppSec e desenvolvedores full-stack, a suíte reúne um motor de **Risk Score Cumulativo do Workspace (0-100)** para Quality Gates, grafo de fluxo de dados (**DataFlow Taint Analysis**), reconhecimento profundo de endpoints (**LinkFinder & JS-Miner**) e uma base unificada de remediação com links oficiais para **OWASP**, **Snyk Learn** e **MITRE CWE** diretamente nos cards de achados.

---

## ✨ Principais Módulos e Funcionalidades

### 1. 📊 Validação de Risk Score Cumulativo do Workspace (0 - 100)
- **Métrica Agregada de Exposição:** Calcula a exposição total de risco do workspace a partir da severidade e da contagem dos achados de segurança detectados pelo motor SAST:
  - **Ponderação por Severidade:**
    - `CRITICAL`: 25 pontos
    - `HIGH`: 15 pontos
    - `MEDIUM`: 6 pontos
    - `LOW`: 2 pontos
    - `INFO`: 0.5 ponto
  - **Função de Saturação Exponencial:**
    $$\text{rawPoints} = (\text{CRIT} \times 25) + (\text{HIGH} \times 15) + (\text{MED} \times 6) + (\text{LOW} \times 2) + (\text{INFO} \times 0.5)$$
    $$\text{Risk Score} = 100 \times \left(1 - e^{-\frac{\text{rawPoints}}{50}}\right)$$
  - **Classificação em 4 Níveis:**
    - `0 - 24`: **Mínimo / Conforme** (Verde)
    - `25 - 49`: **Médio / Atenção** (Amarelo)
    - `50 - 74`: **Alto / Alerta** (Laranja)
    - `75 - 100`: **Crítico / Ação Mandatória** (Vermelho)
- **Quality Gate Interativo no Dashboard & CLI:** Ajuste do teto de risco tolerado (`--max-risk <score>`) com bloqueio imediato do pipeline (exit code `1`) se a pontuação agregada exceder a política da organização.
- **Transparência do Cálculo:** Painel interativo no Dashboard exibindo a decomposição exata de pontos por severidade e a curva de saturação.

---

### 2. ⚖️ Auditoria de Compliance (SOC 2 Type II, ISO 27001, HIPAA)
- **O que é e Como Funciona:** O motor de conformidade audita determinísticamente a base de código e arquivos de infraestrutura contra os requisitos das três principais normas internacionais de segurança:
  - **SOC 2 Type II (Trust Services Criteria):** CC6.1 (Perímetro Lógico e Autenticação), CC6.6 (Proteção contra Ameaças e Vulnerabilidades), CC6.7 (Transmissão Criptográfica Segura), CC7.1 (Monitoramento Contínuo de Vulnerabilidades).
  - **ISO/IEC 27001:2022:** A.8.24 (Uso de Criptografia), A.8.28 (Codificação Segura), A.5.15 (Controle de Acesso), A.8.8 (Gestão de Vulnerabilidades Técnicas).
  - **HIPAA Security Rule:** § 164.312(a)(2)(iv) (Criptografia e Descriptografia de ePHI), § 164.312(c)(1) (Integridade de Dados), § 164.312(e)(1) (Segurança na Transmissão de Redes).
- **Como Usar no Sistema:**
  1. No menu superior, clique na aba **"Auditoria Compliance (SOC2/ISO/HIPAA)"** ou clique em **"💡 Como Usar & Exemplos"** no cabeçalho.
  2. Alterne entre as normas no seletor do topo (**SOC 2**, **ISO 27001** ou **HIPAA**).
  3. Visualize a pontuação de prontidão (**Readiness Score** de 0 a 100%) e o status de cada controle (**COMPLIANT**, **AT_RISK**, **NON_COMPLIANT**).
  4. Clique em um controle para inspecionar os achados do SAST associados a ele e os requisitos mandatórios de evidência.
  5. Clique em **"Exportar Relatório Executivo"** para gerar um pacote formal para auditores externos.
- **Exemplo Prático:**
  - *Cenário:* Aplicação armazena tokens médicos e segredos de banco de dados diretamente em arquivos `.js` ou realiza tráfego HTTP sem TLS.
  - *Código de Entrada:*
    ```typescript
    const dbClient = new PgClient({ connectionString: "postgres://app_user:REDACTED_PASSWORD@prod-db:5432/patients" });
    app.use('/records', unencryptedHttpMiddleware);
    ```
  - *Detecção do SecScan:*
    - **SOC 2 CC6.1 / ISO 27001 A.8.24:** `NON_COMPLIANT` — Credenciais em texto claro expostas no código fonte.
    - **HIPAA § 164.312(a)(2)(iv):** `NON_COMPLIANT` — Ausência de criptografia em repouso e em trânsito de dados de saúde.
  - *Código Remediado:*
    ```typescript
    import { getSecret } from './vault';
    const dbClient = new PgClient({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: true, ca: getSecret('DB_CA_CERT') }
    });
    ```

---

### 3. 📦 SCA — Software Composition Analysis (Dependências, CVEs & Licenças)
- **O que é e Como Funciona:** Analisa o arquivo `package.json` ou manifests de dependências, mapeando bibliotecas de terceiros contra bases conhecidas de vulnerabilidades (NVD/MITRE) e checando termos de licenciamento. Calcula o score de risco das dependências e alerta sobre bibliotecas obsoletas ou licenças copyleft (ex.: GPL v3) incompatíveis com softwares comerciais.
- **Como Usar no Sistema:**
  1. Acesse a aba **"SCA (Dependências & CVEs)"**.
  2. Cole o conteúdo de um `package.json` no painel esquerdo ou utilize o projeto pré-carregado no workspace.
  3. Clique em **"Auditar Dependências"**.
  4. Analise a lista de pacotes com vulnerabilidades catalogadas, CVEs mapeadas, pontuação CVSS e a versão segura de correção (`Fixed In`).
  5. Verifique a matriz de licenças (MIT, Apache-2.0, BSD vs GPL/AGPL).
- **Exemplo Prático:**
  - *Entrada (`package.json`):*
    ```json
    {
      "dependencies": {
        "axios": "0.21.1",
        "lodash": "4.17.15",
        "jsonwebtoken": "8.5.1"
      }
    }
    ```
  - *Detecção do SecScan:*
    - `lodash@4.17.15`: **CVE-2020-8203** (CVSS 7.4 - Prototype Pollution em `zipObjectDeep`). Correção: Atualizar para `>= 4.17.21`.
    - `axios@0.21.1`: **CVE-2020-28168** (CVSS 5.9 - SSRF bypass via redirecionamentos). Correção: Atualizar para `>= 0.21.2`.
  - *Remediação:*
    ```bash
    npm install lodash@^4.17.21 axios@^1.7.0 jsonwebtoken@^9.0.2
    ```

---

### 4. 🐳 IaC Security — Infrastructure as Code (Docker, Kubernetes & CI/CD)
- **O que é e Como Funciona:** Scanner estático especializado em modelos de infraestrutura declarativa: Dockerfile, Kubernetes Manifests (`deployment.yaml`, `pod.yaml`) e workflows de CI/CD (`.github/workflows/*.yml`). Identifica execuções como usuário `root`, ausência de quotas de recursos (DoS), containers privilegiados e injeções de segredos em pipelines.
- **Como Usar no Sistema:**
  1. Abra a aba **"IaC Security (Docker/K8s)"**.
  2. Selecione o tipo de arquivo: **Dockerfile**, **Kubernetes Manifest** ou **GitHub Actions CI/CD**.
  3. Cole o template YAML/Dockerfile ou clique em "Carregar Exemplo Vulnerável".
  4. Clique em **"Escanear Infraestrutura"** para ver a lista de regras violadas com severidade e recomendação de conformidade CIS Benchmark.
- **Exemplo Prático:**
  - *Entrada Vulnerável (`Dockerfile`):*
    ```dockerfile
    FROM node:18-alpine
    WORKDIR /app
    COPY . .
    RUN npm install
    # Risco: Executa como root (sem USER não-privilegiado)
    CMD ["node", "server.js"]
    ```
  - *Detecção do SecScan:*
    - `IAC-DOCKER-001 (HIGH)`: Container executando como `root`. Risco de escape de container e escalada de privilégios.
  - *Remediação Aplicada:*
    ```dockerfile
    FROM node:18-alpine
    WORKDIR /app
    COPY package*.json ./
    RUN npm ci --only=production
    COPY . .
    # Usuário sem privilégios para defesa em profundidade
    USER node
    EXPOSE 3000
    CMD ["node", "server.js"]
    ```

---

### 5. 🎯 DAST — Dynamic Application Security Testing (Fuzzer & Headers)
- **O que é e Como Funciona:** Simula ataques dinâmicos do ponto de vista externo (Black-Box / Gray-Box). Testa rotas HTTP e endpoints REST enviando payloads de fuzzer (SQLi, XSS, Path Traversal, Command Injection) e audita os cabeçalhos de segurança HTTP da resposta do servidor (CSP, HSTS, X-Frame-Options, Permissions-Policy).
- **Como Usar no Sistema:**
  1. Acesse a aba **"DAST (Fuzzer & Headers)"**.
  2. Configure a URL alvo (ex: `https://api.empresa.com/v1/search`), método HTTP (`GET`, `POST`) e o parâmetro a fuzzer (ex: `q` ou `id`).
  3. Escolha os vetores de teste: **SQL Injection**, **Reflected XSS** ou **Command Injection**.
  4. Clique em **"Executar DAST Fuzzer"**.
  5. Copie o comando `cURL` gerado para reproduzir o teste no terminal do seu laboratório.
- **Exemplo Prático:**
  - *Teste de Injeção SQL:*
    ```bash
    curl -X GET "https://api.empresa.com/v1/search?q=%27%20UNION%20SELECT%20null,username,password%20FROM%20users--"
    ```
  - *Auditoria de Headers:*
    - `Strict-Transport-Security (HSTS)`: ❌ AUSENTE (Risco de ataque Man-in-the-Middle e SSL Stripping).
    - `Content-Security-Policy (CSP)`: ❌ AUSENTE (Risco de execução de scripts de terceiros e XSS).
  - *Configuração Remediada no Servidor Express:*
    ```typescript
    import helmet from 'helmet';
    app.use(helmet({
      contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"] } },
      hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
    }));
    ```

---

### 6. 📋 SBOM Generator (OWASP CycloneDX v1.5 & SPDX v2.3)
- **O que é e Como Funciona:** Gera inventários oficiais de componentes de software (Software Bill of Materials) conforme as ordens executivas internacionais de segurança de software e requerimentos de cadeias de suprimento. Extrai metadados, autores, versões, hashes de integridade SHA-256 e termos de licenciamento nos formatos padronizados **CycloneDX v1.5 (JSON/XML)** e **SPDX v2.3 (JSON/Tag-Value)**.
- **Como Usar no Sistema:**
  1. Acesse a aba **"SBOM Generator"**.
  2. Escolha o padrão desejado: **CycloneDX v1.5** ou **SPDX v2.3**.
  3. Escolha a serialização: **JSON** ou **XML / Tag-Value**.
  4. Clique em **"Gerar SBOM"** para inspecionar os componentes catalogados com suas respectivas licenças e hashes criptográficos.
  5. Clique em **"Baixar Arquivo SBOM"** para incluir o artefato no pipeline de liberação de versão.

---

### 7. 🧬 Entropia de Shannon & Varredura Forense de Histórico Git
- **O que é e Como Funciona:** Calcula a entropia da informação de Shannon para cada string suspeita:
  $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  Strings com alta densidade aleatória ($H \ge 4.2$) são classificadas como segredos criptográficos ou chaves de API, mesmo que não possuam prefixos conhecidos. O módulo inclui também um scanner forense de commits para detectar segredos que foram apagados do código atual, mas permanecem vivos no histórico `.git`.
- **Como Usar no Sistema:**
  1. Acesse a aba **"Entropia & Segredos Git"**.
  2. Ajuste a sensibilidade de entropia mínima (padrão: `4.2`).
  3. Clique em **"Calcular Entropia do Workspace"** para ver a tabela de strings ranqueadas pelo valor de Shannon.
  4. Na seção **"Git History Forensics"**, clique em **"Auditar Commits Anteriores"** para inspecionar hashes de commit passados e identificar vazamentos históricos.
- **Exemplo Prático:**
  - *String Detectada:* `"DEMO_HIGH_ENTROPY_SAMPLE_TOKEN_KEY_992182"` (Entropia: `4.89` — **EXTREMAMENTE ALTA**).
  - *Diagnóstico:* Assinatura característica de AWS Secret Key ou token criptográfico de alta aleatoriedade.
  - *Ação Corretiva:* Executar rotação imediata no painel AWS IAM e expurgar do histórico com `git-filter-repo --invert-paths`.

---

### 8. 🎯 Modelagem de Ameaças STRIDE & Calculadora Oficial CVSS v3.1
- **O que é e Como Funciona:** Estrutura formalmente a análise de riscos baseada na metodologia **STRIDE** da Microsoft:
  - **S**poofing (Falsificação de Identidade)
  - **T**ampering (Adulteração de Dados)
  - **R**epudiation (Repúdio de Transações)
  - **I**nformation Disclosure (Vazamento de Informações)
  - **D**enial of Service (Negação de Serviço)
  - **E**levation of Privilege (Escalada de Privilégios)
  Inclui a calculadora oficial **CVSS v3.1** (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability) que gera o vetor canônico e a pontuação determinística (0.0 a 10.0).
- **Como Usar no Sistema:**
  1. Acesse a aba **"Modelagem STRIDE & CVSS"**.
  2. Navegue pelos cards das 6 categorias STRIDE para ver as ameaças mapeadas para a arquitetura do workspace.
  3. Na calculadora CVSS v3.1, selecione as métricas base para calcular o score e obter a string vetorial padronizada (ex.: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8 Critical).

---

### 9. 🔧 Auto-Remediação com Git Unified Diffs (Patches em 1-Clique)
- **O que é e Como Funciona:** Gera patches cirúrgicos no formato padrão **Unified Diff** (`diff --git a/... b/...`) para corrigir automaticamente vulnerabilidades de segredos hardcoded e injeções de código.
- **Como Usar no Sistema:**
  1. Acesse a aba **"Auto-Remediação (Patches)"**.
  2. Visualize a lista de vulnerabilidades corrigíveis.
  3. Inspecione o diff comparativo linha a linha em vermelho (linhas removidas) e verde (linhas adicionadas).
  4. Clique no botão **"Aplicar Correção no Workspace (1-Clique)"** para atualizar o arquivo imediatamente no editor sem necessidade de edição manual.
  5. Ou clique em **"Baixar Arquivo .patch"** para aplicar via terminal com `git apply patch.diff`.
- **Exemplo de Patch Gerado:**
  ```diff
  --- a/src/services/payment.ts
  +++ b/src/services/payment.ts
  @@ -4,2 +4,2 @@
  -const stripeKey = "DEMO_STRIPE_LIVE_KEY_PLACEHOLDER";
  +const stripeKey = process.env.STRIPE_SECRET_KEY;
  ```

---

### 10. ⚡ IAST — Interactive Application Security Testing (Runtime Hooks)
- **O que é e Como Funciona:** O motor IAST injeta sensores (hooks) nos sinks de execução mais sensíveis da aplicação Node.js (`eval()`, `Function()`, `child_process.exec()`, consultas de banco de dados e métodos de resposta HTTP). Diferente do SAST puro, o IAST rastreia o valor concreto das variáveis durante a execução, confirmando se dados não confiáveis realmente alcançam o destino perigoso.
- **Como Usar no Sistema:**
  1. Acesse a aba **"IAST (Runtime Hooks)"**.
  2. Visualize os sinks monitorados e os gatilhos disparados em tempo real.
  3. Execute testes interativos enviando requisições com dados manipulados para observar a captura de stack trace e o fluxo de dados em memória.

---

### 11. 🛡️ Frameworks Cruzados (MITRE ATT&CK, NIST CSF 2.0 & OWASP WSTG)
- **O que é e Como Funciona:** Mapeia todos os achados de vulnerabilidade do projeto para os catálogos universais da indústria:
  - **MITRE ATT&CK:** Táticas de Acesso Inicial (TA0001), Execução (TA0002), Coleta de Credenciais (TA0006) e Exfiltração (TA0010).
  - **NIST CSF 2.0:** Categorias de Governança (GV), Identificação (ID), Proteção (PR) e Detecção (DE).
  - **OWASP WSTG v4.2:** Web Security Testing Guide com testes práticos de validação de autenticação, sessão e injeção.
- **Como Usar no Sistema:**
  1. Acesse a aba **"Frameworks (MITRE/NIST/OWASP)"**.
  2. Filtre por tática MITRE ou função NIST.
  3. Visualize os controles associados, as técnicas adversárias mapeadas e o status de cobertura do seu projeto.

---

### 12. 💡 Manual de Uso & Guia Interativo de Ferramentas
- **Botão Rápido no Topo:** Clique em **`💡 Como Usar & Exemplos`** em qualquer tela do SecScan.
- **Busca e Categorias:** Filtre ferramentas por categoria (*Conformidade & Governança*, *AppSec & SAST*, *Defesa & Runtime*, *Infraestrutura & DevSecOps*).
- **Conteúdo em Três Seções:**
  1. **Como Funciona:** Arquitetura e detalhes técnicos sob o capô.
  2. **Passo a Passo:** Instruções práticas para operar a ferramenta no SecScan.
  3. **Exemplo Prático Completo:** Cenário, código de entrada, diagnóstico gerado pelo sistema e snippet com a solução corrigida (com botão de cópia em 1 clique).
- **Atalho Direto:** Botão **"Ir para a Ferramenta"** para navegar imediatamente para o módulo desejado.

---

### 13. 📚 Base de Dados de Remediação com Referências Oficiais (OWASP, Snyk, CWE)
- **Links Oficiais em Tempo Real nos Cards de Achados:** Cada card de vulnerabilidade identificado pelo motor SAST renderiza links diretos e contextualizados para:
  - **OWASP Cheat Sheet Series:** *Key Management*, *Secrets Management*, *Cryptographic Storage*, *DOM-based XSS Prevention*, *Node.js Security*.
  - **OWASP Top 10:** *A01:2021 Broken Access Control*, *A02:2021 Cryptographic Failures*, *A03:2021 Injection*, *A07:2021 Identification and Authentication Failures*.
  - **Snyk Learn Advisories:** Artigos educativos e guias práticos (*Hardcoded Credentials*, *API Key Leakage*, *JWT Security*, *Command Injection*).
  - **MITRE CWE:** Especificações canônicas (*CWE-798*, *CWE-200*, *CWE-312*, *CWE-259*, *CWE-327*, *CWE-79*, *CWE-78*).
- **Playbooks de Correção Passo a Passo:** Guias interativos incluindo comandos de expurgo de histórico Git (`git-filter-repo`), rotação de credenciais ativas, snippets comparativos (*Before vs. After*) e medidas preventivas de arquitetura.
- **Wiki Modal Integrada:** Navegue por toda a base de conhecimento de remediação categorizada por tipo de vulnerabilidade.

---

### 14. 🌊 Grafo de Fluxo de Dados (DataFlow Graph & Taint Analysis)
- **Rastreamento Ponto a Ponto:** Mapeamento visual e algorítmico do fluxo de dados:
  - **Sources (Fontes):** Endpoints de API, rotas HTTP e parâmetros de requisição (`req.query`, `req.body`, `window.location`).
  - **Consumers (Consumidores):** Funções intermediárias e handlers que processam as variáveis.
  - **Sanitizers (Higienizadores):** Validações e métodos de sanitização (ex.: `DOMPurify.sanitize`, `encodeURIComponent`).
  - **Sinks Perigosos:** Destinos arriscados como `innerHTML`, `dangerouslySetInnerHTML`, `child_process.exec`, `eval`, `document.write`.
- **Tutorial Interativo Integrado (`DataFlowTutorialOverlay`):** Guia interativo integrado ao container do grafo com dicas sobre navegação, pan, zoom, layout e interpretação da trilha de contaminação (taint analysis).

---

### 15. 🛰️ JS-Miner & LinkFinder Recon Engine
- **Source Maps Discovery:** Identificação de arquivos `.map` que possam expor código não transpilado em ambientes de produção.
- **Cloud Storage Buckets:** Busca por referências a buckets S3 da AWS, Google Cloud Storage e Azure Blob Storage.
- **Extração Profunda de Endpoints:** Reconhecimento automático de rotas REST, GraphQL, chamadas `fetch()`, `axios` e mapeamento de superfícies de ataque internas/administrativas (`/api/admin/*`, `/internal/*`).

---

### 16. 🛡️ Defesa e Infraestrutura de Aplicações Web (WAF - Web Application Firewall)
- **Painel de Inspeção & Telemetria em Tempo Real:** Monitoramento dinâmico de tráfego HTTP/HTTPS com estatísticas de requisições inspecionadas, taxa de bloqueio (Block Rate), RPS e latência de inspeção (P95/P99).
- **Cobertura OWASP Top 10 & Virtual Patching:**
  - `SQL Injection (SQLi)`: Detecção de UNION, boolean/time-based payloads.
  - `Cross-Site Scripting (XSS)`: Sanitização de scripts reflexivos e baseados em DOM.
  - `Remote Code Execution (RCE)` e `Local/Remote File Inclusion (LFI/RFI)`.
  - `Server-Side Request Forgery (SSRF)`.
- **Proteção Anti-DDoS e Rate Limiting:** Controles granulares por IP e rota (ex.: rotas de login `/api/v1/auth/login` e `/checkout`).
- **Simulador de Requisições HTTP Interativo:** Envio de requisições com teste em tempo real de payloads maliciosos, avaliação do motor de regras e indicação clara de decisão (`BLOCKED` vs `ALLOWED`).
- **Gerenciador de Regras e ACLs:** Listas de bloqueio por IP/CIDR, geo-blocking e criação de regras customizadas.

---

### 17. 🌐 SD-WAN Corporativo (Software-Defined WAN Suite)
- **Topologia de Túneis e Edge Routers:** Visualização da malha SD-WAN com nós de borda (Hub HQ, Branch Offices, Multi-Cloud Gateways AWS/GCP/Azure).
- **Políticas de Roteamento Baseadas em SLA (Application-Aware Routing):**
  - Monitoramento contínuo de Latência (ms), Jitter (ms) e Perda de Pacotes (%).
  - Steering automático de tráfego crítico (VoIP, Videoconferência, SaaS ERP) para links primários (MPLS, Fibra Dedicada) ou failover inteligente para 5G/Banda Larga.
- **Túneis IPsec & Zero-Trust Mesh:** Criptografia ponta a ponta (AES-256-GCM / WireGuard) com monitoramento de status e rotação de chaves.
- **Failover e Simulação de Tráfego:** Painel de simulação para testar degradação de links e conferir a reação dinâmica da malha SD-WAN em tempo real.

---

### 18. 🎯 EDR (Endpoint Detection & Response) & Live Response Suite
- **Inventário de Endpoints & Telemetria em Tempo Real:**
  - Descoberta e monitoramento de hosts com status de saúde do agente, carga de CPU/Memória e integridade do driver eBPF.
  - Ações cirúrgicas de contenção host com isolamento preventivo a nível de kernel (Zero Trust Host Containment).
- **Árvore de Execução & Parent-Child Process Tracking:**
  - Rastreamento hierárquico de processos (`PID`, `PPID`, usuário, integrity level e linha de comando executada).
  - Identificação de bifurcações perigosas (ex: processo web Node.js/Python spawnando `/bin/sh` ou PowerShell).
  - Encerramento cirúrgico em tempo real de árvores inteiras de processos maliciosos (`SIGKILL`).
- **Regras Comportamentais de Indicadores de Ataque (IOA) & MITRE ATT&CK:**
  - Assinaturas comportamentais para execução de LOLBins, dumping de credenciais em `.env`, process hollowing e conexões reversas para redes Tor/C2.
- **Real-Time Response (RTR Terminal):**
  - Sessão interativa remota direta com os sensores dos endpoints para coleta de evidências e execução de comandos de remediação (`ps`, `netstat`, `kill`, `isolate`, `quarantine`).
- **Threat Hunting Ativo (KQL / Query Syntax):**
  - Motor de busca em telemetria histórica de eventos de processos, sockets e modificações de arquivos com playbooks prontos para LOLBins, exfiltração DNS e injeção de bibliotecas (`LD_PRELOAD`).
- **Playbooks Automatizados de Resposta a Incidentes (SOAR):**
  - Orquestração de ações defensivas imediatas com disparos automáticos ou validação por operador humano.
- **Cofre Centralizado de Indicadores de Comprometimento (IOCs):**
  - Gerenciamento de hashes SHA-256, IPs maliciosos, FQDNs e caminhos de arquivos sincronizados dinamicamente com os agentes locais.
- **Forense de Memória & Assinaturas YARA:**
  - Varredura de dumps de memória de processos suspeitos para extração de credenciais, detecção de DLLs injetadas e identificação de regiões RWX violadas.

---

### 19. 🛡️ Módulos Complementares de Segurança de Rede
- **Proteção DNS (DNS Security):** Detecção de DNS Tunneling, filtragem de domínios maliciosos e DGA (Domain Generation Algorithms), e validação de DNSSEC / DoH.
- **Firewall de Próxima Geração (NGFW) & IDS/IPS:** Inspeção profunda de pacotes (DPI), controle de aplicações L7 e assinaturas de intrusão Snort/Suricata.

---

### 20. ⚙️ Motor de Regras Customizáveis (Custom Regex)
- Criação e validação dinâmica de regras regex customizadas na interface ou via arquivo JSON, com suporte a categorias personalizadas, severidade e limiar de entropia mínima.

---

### 21. 🚀 CI/CD & Automação DevSecOps
- Exportação instantânea em múltiplos formatos: **SARIF 2.1.0** (nativamente renderizado na aba *Security > Code Scanning* do GitHub), **JSON Estruturado** e **CSV**.
- Interface de Linha de Comando (CLI) executável em qualquer ambiente Node.js com qualidade gate duplo: por severidade (`--fail-on critical`) e por pontuação de risco cumulativo (`--max-risk <score>`).

---

## 💻 Interface de Linha de Comando (CLI)

A suíte inclui o executável nativo em Node.js (`bin/secscan.js`):

```bash
# Executar auditoria completa no diretório atual
node bin/secscan.js .

# Executar via atalho do npm
npm run secscan

# Bloquear pipeline caso o Risk Score Cumulativo ultrapasse 50 (Quality Gate)
node bin/secscan.js . --max-risk 50

# Bloquear pipeline caso existam achados com severidade crítica
node bin/secscan.js . --fail-on critical

# Gerar relatório SARIF 2.1.0 para GitHub Code Scanning
node bin/secscan.js . --format sarif --output secscan-results.sarif

# Ignorar pastas de teste ou dependências adicionais
node bin/secscan.js . --ignore "tests/*,docs/*,temp"

# Carregar regras regex customizadas corporativas
node bin/secscan.js . --rules ./my-custom-rules.json
```

### Parâmetros da CLI

| Parâmetro | Descrição | Padrão |
|---|---|---|
| `[diretório]` | Caminho do diretório raiz a ser auditado | `.` |
| `--max-risk <score>` | **Quality Gate:** Retorna exit code `1` se o Risk Score Cumulativo (0-100) exceder o limite | Desativado |
| `--fail-on <severidade>` | Retorna exit code `1` se houver alertas (`critical`, `high`, `medium`) | Desativado |
| `--format <formato>` | Formato de saída (`table`, `json`, `sarif`, `csv`) | `table` |
| `--rules <arquivo.json>` | Arquivo JSON com regras regex customizadas | Regras internas |
| `--ignore <patterns>` | Padrões glob adicionais a ignorar | `node_modules, vendor, dist...` |
| `--output <arquivo>` | Salva a saída no arquivo indicado | `stdout` |

---

## 🔄 Pipeline CI/CD GitHub Actions com SARIF e Quality Gate

Integração com GitHub Actions em [`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml):

```yaml
name: SecScan AppSec Analysis & Quality Gate

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

permissions:
  contents: read
  security-events: write # Necessário para publicar o relatório SARIF

jobs:
  sast-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js 22
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'npm'
      - name: Install dependencies
        run: npm ci
      - name: Run SecScan SAST (SARIF Report)
        run: |
          node bin/secscan.js . \
            --format sarif \
            --output secscan-results.sarif \
            --ignore "node_modules,dist,build,vendor"
      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-results.sarif
      - name: Quality Gate (Cumulative Risk Score <= 50)
        run: |
          node bin/secscan.js . --max-risk 50 --fail-on critical
```

---

## 🛠️ Execução Local do Dashboard Web

```bash
# Instalar dependências
npm install

# Iniciar servidor de desenvolvimento (Porta 3000)
npm run dev

# Compilar para produção
npm run build
```

---

## 🌍 Portabilidade e Hospedagem Externa (Deploy fora do AI Studio)

**Sim, todo o código do repositório é 100% funcional e portável!** 

A aplicação foi construída como uma SPA (Single Page Application) moderna em **React 18 + TypeScript + Vite + Tailwind CSS**, sem dependências proprietárias travadas ao AI Studio:

- **Hospedagem Estática Imediata:** Pode ser hospedada gratuitamente em plataformas como **Vercel**, **Netlify**, **Cloudflare Pages**, **GitHub Pages**, **AWS S3/CloudFront** ou qualquer servidor web tradicional (Nginx, Apache, Caddy).
  - Basta executar `npm run build`, e o diretório `dist/` resultante conterá todos os arquivos HTML, CSS e bundles JS estáticos e otimizados.
- **Configuração Simples para Vercel / Netlify:**
  - **Build Command:** `npm run build`
  - **Output Directory:** `dist`
  - **Node Version:** 18+ ou 20+
- **Execução em Containers Docker:**
  - O projeto pode ser facilmente empacotado em uma imagem Docker com Nginx Alpine para servir o conteúdo estático ou orquestrado em Kubernetes / AWS ECS / Google Cloud Run.
- **Autonomia da CLI:** O utilitário `bin/secscan.js` roda de forma 100% independente em pipelines CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure DevOps) precisando apenas do runtime Node.js padrão.

---

*SecScan AppSec Suite • Análise Estática de Segurança, Rastreamento de Fluxo de Dados e Quality Gates com referências oficiais OWASP, Snyk e MITRE CWE.*
