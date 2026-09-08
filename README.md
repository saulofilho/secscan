# 🛡️ SecScan - JavaScript & TypeScript Secret / API Path Static Scanner

[![CI/CD Security Analysis](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF?logo=github-actions&logoColor=white)](.github/workflows/ci-cd.yml)
[![Node.js 22](https://img.shields.io/badge/Node.js-22%20LTS-339933?logo=nodedotjs&logoColor=white)](package.json)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0%20Standard-4B32C3?logo=github&logoColor=white)](https://sarifweb.azurewebsites.net/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/Demo-GitHub%20Pages-brightgreen)](https://pages.github.com/)

**SecScan** é uma ferramenta de ponta a ponta para **Análise Estática de Segurança (SAST)** e auditoria contínua de código JavaScript/TypeScript. Ele analisa automaticamente repositórios em busca de **chaves de API expostas, segredos, senhas e endpoints críticos de API**, ignorando nativamente dependências de terceiros (`node_modules`, `vendor`, `dist`).

Conta com um **Web Dashboard centralizado** para métricas e monitoramento de logs em tempo real, além de uma **Interface de Linha de Comando (CLI)** de alto desempenho para automação e bloqueio de merges em pipelines CI/CD.

---

## ✨ Principais Funcionalidades

- 🔍 **Detecção Abrangente de Segredos:**
  - Chaves de Nuvem: AWS Access Key ID (`AKIA...`), AWS Secret Access Key, Google Cloud & Gemini API (`AIzaSy...`).
  - Tokens de Autenticação: GitHub PATs (`ghp_...`, `github_pat_...`), JWTs (`eyJ...`), Slack Webhooks e bot tokens.
  - Pagamentos & Finanças: Chaves secretas da Stripe (`sk_live_...`, `rk_live_...`).
  - Bancos de Dados & Senhas: URIs com credenciais (`postgres://`, `mongodb://`, `mysql://`, `redis://`), atribuições de senhas (`password = "..."`).
  - Inteligência Artificial: Chaves secretas da OpenAI (`sk-...`), SendGrid (`SG....`).
  - Chaves Criptográficas: Chaves privadas PEM/RSA/SSH (ex.: blocos de certificados e chaves assimétricas).

- 🚫 **Filtro Automático de Dependências de Terceiros:**
  - Ignora rigorosamente diretórios de bibliotecas externas: `node_modules/`, `vendor/`, `bower_components/`, `.git/`, além de pastas de build `dist/`, `build/`, `.cache/` e arquivos minificados `*.min.js` ou bundles.

- 🌐 **Mapeamento de Rotas e Endpoints de API:**
  - Extrai automaticamente caminhos de rotas REST, URLs completas, chamadas `fetch()`, `axios` e `express/router`.
  - Sinaliza endpoints de risco administrativo ou interno (ex: `/api/v1/admin/refunds`, `/internal/metrics`, `/auth/token`).

- 🧮 **Cálculo de Entropia de Shannon:**
  - Identifica strings de alta aleatoriedade criptográfica para prevenir falsos positivos e destacar credenciais vazadas.

- ⚙️ **Regras Customizadas via Regex:**
  - Crie, teste e exporte suas próprias regras de regex com categorias, severidade (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) e limiar de entropia.

- 📊 **Web Dashboard Centralizado:**
  - Gráficos de distribuição por severidade, score de conformidade OWASP / CIS, visualizador de código com segredos mascarados (`••••••••`) e logs de auditoria em tempo real.

- 🚀 **Exportação para CI/CD:**
  - Exporta relatórios nos formatos **JSON estruturado**, **CSV** para planilhas e **SARIF 2.1.0** (integrado nativamente com a aba *Security > Code Scanning* do GitHub).

---

## 💻 Interface de Linha de Comando (CLI)

O SecScan inclui um executável CLI nativo em Node.js (`bin/secscan.js`):

```bash
# Executar scan no diretório atual
node bin/secscan.js .

# Executar via npm script
npm run secscan

# Gerar relatório JSON detalhado para CI/CD
node bin/secscan.js . --format json --output secscan-report.json

# Gerar relatório no padrão SARIF para GitHub Security
node bin/secscan.js . --format sarif --output secscan-results.sarif

# Bloquear pipeline caso haja segredos de severidade crítica ou alta
node bin/secscan.js . --fail-on critical

# Adicionar regras de exclusão adicionais
node bin/secscan.js . --ignore "tests/*,docs/*,temp"

# Utilizar arquivo de regras personalizadas
node bin/secscan.js . --rules ./my-custom-rules.json
```

### Flags da CLI

| Parâmetro | Descrição | Padrão |
|---|---|---|
| `[diretório]` | Caminho do diretório raiz a ser analisado | `.` |
| `--format <formato>` | Formato da saída (`table`, `json`, `sarif`, `csv`) | `table` |
| `--rules <arquivo.json>` | Arquivo JSON com regras regex customizadas | Regras padrão |
| `--ignore <patterns>` | Padrões de arquivos/pastas adicionais a ignorar | `node_modules, vendor, dist...` |
| `--fail-on <severidade>` | Retorna código de saída `1` se houver alertas (`critical`, `high`, `medium`) | Desativado |
| `--output <arquivo>` | Salva a saída diretamente no arquivo indicado | `stdout` |
| `--help` | Exibe a ajuda com exemplos | - |

---

## 🔄 Automação CI/CD no GitHub Actions

A pipeline automatizada já está configurada em [`.github/workflows/ci-cd.yml`](.github/workflows/ci-cd.yml) utilizando **Node.js 22**:

```yaml
name: SecScan CI/CD & Security Analysis

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

permissions:
  contents: read
  security-events: write # Permite envio de SARIF para a aba Security

jobs:
  security-scan:
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

      - name: Run SecScan SAST (Generate SARIF & JSON)
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

      - name: Quality Gate (Fail on Critical)
        run: |
          node bin/secscan.js . --fail-on critical
```

---

## 🌐 Deploy no GitHub Pages

O fluxo para deploy contínuo do Web Dashboard no GitHub Pages encontra-se em [`.github/workflows/deploy-pages.yml`](.github/workflows/deploy-pages.yml).

### Passos para ativar no seu repositório:
1. No seu repositório no GitHub, vá em **Settings** > **Pages**.
2. Em **Build and deployment** > **Source**, selecione **GitHub Actions**.
3. Faça um push para a branch `main`: a Action executará a compilação no Node 22 e publicará o dashboard automaticamente na URL do seu GitHub Pages!

---

## 📝 Formato de Regras Customizadas (Regex JSON)

Você pode criar um arquivo `rules.json` contendo regras customizadas para sua empresa:

```json
[
  {
    "id": "sec-internal-api-token",
    "name": "Token Interno Corporativo",
    "pattern": "\\bCORP-[A-Z0-9]{24}\\b",
    "flags": "g",
    "category": "API_KEY",
    "severity": "CRITICAL",
    "description": "Token de autenticação dos microsserviços internos.",
    "remediation": "Obtenha tokens dinâmicos via serviço Vault.",
    "minEntropy": 3.8,
    "enabled": true
  }
]
```

---

## ☁️ Boas Práticas e Integração com Serviços de Nuvem

Em vez de armazenar segredos no código-fonte ou em arquivos versionados:

1. **AWS Secrets Manager & KMS:**
   - Injete credenciais em tempo de execução via SDK `@aws-sdk/client-secrets-manager` ou utilize IAM Roles em instâncias ECS/EKS/Lambda.
2. **Google Cloud Secret Manager:**
   - Utilize `@google-cloud/secret-manager` e vincule Service Accounts com privilégio mínimo.
3. **Variáveis de Ambiente Protegidas:**
   - Armazene chaves em arquivos `.env` listados estritamente no `.gitignore` e injete variáveis protegidas na pipeline de deploy.

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

*Desenvolvido com foco em DevSecOps, conformidade com OWASP Top 10 e proteção contra vazamento acidental de credenciais.*
