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

### 2. 📚 Base de Dados de Remediação com Referências Oficiais (OWASP, Snyk, CWE)
- **Links Oficiais em Tempo Real nos Cards de Achados:** Cada card de vulnerabilidade identificado pelo motor SAST renderiza links diretos e contextualizados para:
  - **OWASP Cheat Sheet Series:** *Key Management*, *Secrets Management*, *Cryptographic Storage*, *DOM-based XSS Prevention*, *Node.js Security*.
  - **OWASP Top 10:** *A01:2021 Broken Access Control*, *A02:2021 Cryptographic Failures*, *A03:2021 Injection*, *A07:2021 Identification and Authentication Failures*.
  - **Snyk Learn Advisories:** Artigos educativos e guias práticos (*Hardcoded Credentials*, *API Key Leakage*, *JWT Security*, *Command Injection*).
  - **MITRE CWE:** Especificações canônicas (*CWE-798*, *CWE-200*, *CWE-312*, *CWE-259*, *CWE-327*, *CWE-79*, *CWE-78*).
- **Playbooks de Correção Passo a Passo:** Guias interativos incluindo comandos de expurgo de histórico Git (`git-filter-repo`), rotação de credenciais ativas, snippets comparativos (*Before vs. After*) e medidas preventivas de arquitetura.
- **Wiki Modal Integrada:** Navegue por toda a base de conhecimento de remediação categorizada por tipo de vulnerabilidade.

### 3. 🌊 Grafo de Fluxo de Dados (DataFlow Graph & Taint Analysis)
- **Rastreamento Ponto a Ponto:** Mapeamento visual e algorítmico do fluxo de dados:
  - **Sources (Fontes):** Endpoints de API, rotas HTTP e parâmetros de requisição (`req.query`, `req.body`, `window.location`).
  - **Consumers (Consumidores):** Funções intermediárias e handlers que processam as variáveis.
  - **Sanitizers (Higienizadores):** Validações e métodos de sanitização (ex.: `DOMPurify.sanitize`, `encodeURIComponent`).
  - **Sinks Perigosos:** Destinos arriscados como `innerHTML`, `dangerouslySetInnerHTML`, `child_process.exec`, `eval`, `document.write`.
- **Tutorial Interativo Integrado (`DataFlowTutorialOverlay`):** Guia interativo integrado ao container do grafo com dicas sobre navegação, pan, zoom, layout e interpretação da trilha de contaminação (taint analysis).

### 4. 🔍 Matriz de Detecção de Segredos & Entropia de Shannon
- **Cobertura Extensa de Padrões:**
  - **Nuvem:** AWS Access Key ID (`AKIA...`), Secret Access Key, Google Cloud API & Gemini (`AIzaSy...`), Azure.
  - **Autenticação:** GitHub Tokens (`ghp_...`, `github_pat_...`), JWTs (`eyJ...`), Slack Webhooks e bot tokens.
  - **Finanças & Pagamentos:** Chaves secretas da Stripe (`sk_live_...`, `rk_live_...`).
  - **Bancos de Dados:** URIs completas com credenciais (`postgres://`, `mongodb://`, `mysql://`, `redis://`).
  - **IA & LLMs:** OpenAI API Keys (`sk-proj-...`, `sk-...`), Anthropic, HuggingFace.
  - **Criptografia & Infra:** Chaves privadas PEM, RSA, SSH e blocos de certificados.
- **Cálculo de Entropia de Shannon:** Medição da densidade de informação para mitigar falsos positivos e capturar chaves simétricas pseudoaleatórias.
- **Ponderação por Criticidade de Arquivo:** Avaliação do risco contextual do achado baseado na sensibilidade do arquivo (`.env`, `docker-compose`, `k8s/`, rotas de backend vs. testes).

### 5. 🛰️ JS-Miner & LinkFinder Recon Engine
- **Source Maps Discovery:** Identificação de arquivos `.map` que possam expor código não transpilado em ambientes de produção.
- **Cloud Storage Buckets:** Busca por referências a buckets S3 da AWS, Google Cloud Storage e Azure Blob Storage.
- **Extração Profunda de Endpoints:** Reconhecimento automático de rotas REST, GraphQL, chamadas `fetch()`, `axios` e mapeamento de superfícies de ataque internas/administrativas (`/api/admin/*`, `/internal/*`).

### 6. ⚙️ Motor de Regras Customizáveis (Custom Regex)
- Criação e validação dinâmica de regras regex customizadas na interface ou via arquivo JSON, com suporte a categorias personalizadas, severidade e limiar de entropia mínima.

### 7. 🚀 CI/CD & Automação DevSecOps
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

*SecScan AppSec Suite • Análise Estática de Segurança, Rastreamento de Fluxo de Dados e Quality Gates com referências oficiais OWASP, Snyk e MITRE CWE.*
