import { ScannedFile } from '../types';

export interface IacFinding {
  id: string;
  ruleId: string;
  title: string;
  category: 'DOCKER' | 'KUBERNETES' | 'TERRAFORM' | 'COMPOSE' | 'CICD';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  file: string;
  line: number;
  snippet: string;
  description: string;
  remediation: string;
  compliance?: {
    cisBenchmark?: string;
    nist?: string;
  };
  suggestedPatch?: string;
}

export interface IacReport {
  totalFilesScanned: number;
  passedChecks: number;
  failedChecks: number;
  iacPostureScore: number;
  findings: IacFinding[];
  summaryByTech: {
    DOCKER: { count: number; critical: number; high: number };
    KUBERNETES: { count: number; critical: number; high: number };
    TERRAFORM: { count: number; critical: number; high: number };
    COMPOSE: { count: number; critical: number; high: number };
    CICD: { count: number; critical: number; high: number };
  };
}

export function scanInfrastructureAsCode(files: ScannedFile[]): IacReport {
  const findings: IacFinding[] = [];
  let totalFilesScanned = 0;

  for (const file of files) {
    const fileName = file.name.toLowerCase();
    const filePath = file.path.toLowerCase();
    const lines = file.content.split('\n');

    // ==========================================
    // 1. Dockerfile / Containerfile Audits
    // ==========================================
    if (fileName === 'dockerfile' || fileName.endsWith('.dockerfile') || fileName === 'containerfile') {
      totalFilesScanned++;
      let hasUserDirective = false;

      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        const lineNum = idx + 1;

        if (trimmed.startsWith('USER ') && !trimmed.includes('root') && !trimmed.includes('0')) {
          hasUserDirective = true;
        }

        // Docker Rule 1: Mutable / Latest base image
        if (/^FROM\s+([a-zA-Z0-9_\-\.\/]+)(?::latest)?(?:\s|$)/i.test(trimmed) && (trimmed.includes(':latest') || !trimmed.includes(':'))) {
          findings.push({
            id: `iac-docker-latest-${idx}`,
            ruleId: 'IAC-DOCKER-001',
            title: 'Base Image Utiliza Tag Instável (:latest ou sem tag)',
            category: 'DOCKER',
            severity: 'HIGH',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'Imagens base usando a tag :latest ou sem pinning de versão introduzem quebras e vulnerabilidades silenciosas em compilações futuras.',
            remediation: 'Especifique uma tag semântica imutável ou digest SHA-256 (ex: node:20.11.1-alpine ou node@sha256:...).',
            compliance: { cisBenchmark: 'CIS Docker 4.1', nist: 'NIST SP 800-190' },
            suggestedPatch: line.replace(':latest', ':20-alpine')
          });
        }

        // Docker Rule 2: Installing SSH or Sudo
        if (/RUN\s+.*(openssh-server|sudo|telnet)/i.test(trimmed)) {
          findings.push({
            id: `iac-docker-ssh-${idx}`,
            ruleId: 'IAC-DOCKER-002',
            title: 'Pacotes Inseguros Instalados (SSH / Sudo)',
            category: 'DOCKER',
            severity: 'CRITICAL',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'Instalar servidores SSH ou utilitários de escalonamento sudo dentro de containers viola o princípio de responsabilidade única e cria portas de entrada para invasão.',
            remediation: 'Utilize comandos remotos via docker exec ou kubectl exec em vez de embutir daemons SSH.',
            compliance: { cisBenchmark: 'CIS Docker 4.4', nist: 'NIST SP 800-190 Sec 3.1' }
          });
        }

        // Docker Rule 3: Exposing sensitive administration ports
        if (/EXPOSE\s+.*(22|3389|9200|2375)/i.test(trimmed)) {
          findings.push({
            id: `iac-docker-ports-${idx}`,
            ruleId: 'IAC-DOCKER-003',
            title: 'Exposição de Portas de Gerenciamento Sensíveis (22/3389/2375)',
            category: 'DOCKER',
            severity: 'CRITICAL',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'O Dockerfile declara a exposição de portas administrativas que não devem ser expostas em containers de aplicação.',
            remediation: 'Remova a diretiva EXPOSE 22 e mantenha apenas as portas de serviço da aplicação (ex: 3000 ou 8080).',
            compliance: { cisBenchmark: 'CIS Docker 4.5' },
            suggestedPatch: line.replace('22', '').trim()
          });
        }
      });

      // Docker Rule 4: Running as Root without USER
      if (!hasUserDirective) {
        findings.push({
          id: `iac-docker-root-${file.path}`,
          ruleId: 'IAC-DOCKER-004',
          title: 'Container Executado como Root (Ausência de Diretiva USER)',
          category: 'DOCKER',
          severity: 'CRITICAL',
          file: file.path,
          line: lines.length,
          snippet: lines[lines.length - 1] || 'CMD ["npm", "start"]',
          description: 'A imagem não define uma diretiva USER não-root. Caso a aplicação sofra RCE (Remote Code Execution), o atacante obterá privilégios de root no host/namespace.',
          remediation: 'Crie um usuário de sistema e declare `USER appuser` antes da instrução ENTRYPOINT ou CMD.',
          compliance: { cisBenchmark: 'CIS Docker 4.1', nist: 'NIST SP 800-190 Sec 4.1' },
          suggestedPatch: 'RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser\n' + (lines[lines.length - 1] || '')
        });
      }
    }

    // ==========================================
    // 2. Docker Compose Audits
    // ==========================================
    if (fileName.includes('compose') && (fileName.endsWith('.yml') || fileName.endsWith('.yaml'))) {
      totalFilesScanned++;
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        const lineNum = idx + 1;

        if (trimmed.includes('privileged: true')) {
          findings.push({
            id: `iac-compose-privileged-${idx}`,
            ruleId: 'IAC-COMPOSE-001',
            title: 'Container em Modo Privilegiado (privileged: true)',
            category: 'COMPOSE',
            severity: 'CRITICAL',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'Modo privilegiado desativa o isolamento do kernel Linux, concedendo ao container acesso direto aos dispositivos e memória do host.',
            remediation: 'Remova privileged: true e declare apenas as capabilities necessárias via cap_add.',
            compliance: { cisBenchmark: 'CIS Docker 5.4' }
          });
        }

        if (trimmed.includes('/var/run/docker.sock')) {
          findings.push({
            id: `iac-compose-sock-${idx}`,
            ruleId: 'IAC-COMPOSE-002',
            title: 'Montagem Perigosa do Socket do Docker (/var/run/docker.sock)',
            category: 'COMPOSE',
            severity: 'CRITICAL',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'Montar o socket do daemon docker permite que qualquer processo no container controle o daemon do host, resultando em container breakout imediato.',
            remediation: 'Isole a comunicação via API de orquestração segura sem montar o socket unix.',
            compliance: { cisBenchmark: 'CIS Docker 5.31' }
          });
        }

        if (trimmed.includes('0.0.0.0:5432') || trimmed.includes('0.0.0.0:3306') || trimmed.includes('0.0.0.0:27017')) {
          findings.push({
            id: `iac-compose-db-expose-${idx}`,
            ruleId: 'IAC-COMPOSE-003',
            title: 'Banco de Dados Exposto Publicamente em Todas as Interfaces',
            category: 'COMPOSE',
            severity: 'HIGH',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'A porta padrão do banco de dados está vinculada a 0.0.0.0, expondo o banco à rede pública em vez de ficar restrito à rede interna do Compose.',
            remediation: 'Vincule a 127.0.0.1 (ex: "127.0.0.1:5432:5432") ou use apenas expose interno.',
            suggestedPatch: line.replace('0.0.0.0:', '127.0.0.1:')
          });
        }
      });
    }

    // ==========================================
    // 3. Kubernetes Manifests Audits
    // ==========================================
    if ((fileName.endsWith('.yaml') || fileName.endsWith('.yml')) && (file.content.includes('apiVersion:') && (file.content.includes('kind: Deployment') || file.content.includes('kind: Pod')))) {
      totalFilesScanned++;
      const content = file.content;

      if (content.includes('privileged: true')) {
        findings.push({
          id: `iac-k8s-priv-${file.path}`,
          ruleId: 'IAC-K8S-001',
          title: 'Pod Kubernetes Configurado como Privilegiado',
          category: 'KUBERNETES',
          severity: 'CRITICAL',
          file: file.path,
          line: 1,
          snippet: 'securityContext:\n  privileged: true',
          description: 'Containers privilegiados têm acesso a todos os dispositivos no host e desabilitam grande parte das restrições de namespace do Linux.',
          remediation: 'Defina `securityContext.privileged: false` e ative `securityContext.allowPrivilegeEscalation: false`.',
          compliance: { cisBenchmark: 'CIS Kubernetes 5.2.1' }
        });
      }

      if (!content.includes('resources:') || (!content.includes('limits:') && !content.includes('requests:'))) {
        findings.push({
          id: `iac-k8s-limits-${file.path}`,
          ruleId: 'IAC-K8S-002',
          title: 'Ausência de Limites de CPU e Memória (Risco de DoS)',
          category: 'KUBERNETES',
          severity: 'MEDIUM',
          file: file.path,
          line: 1,
          snippet: 'spec.containers[0]',
          description: 'Containers sem limits/requests de CPU e memória podem consumir recursos de todo o cluster em caso de fuga de memória ou ataque de DoS.',
          remediation: 'Configure os blocos `resources.limits` e `resources.requests` com limites seguros.',
          compliance: { cisBenchmark: 'CIS Kubernetes 5.4.1' }
        });
      }

      if (content.includes('hostPath:')) {
        findings.push({
          id: `iac-k8s-hostpath-${file.path}`,
          ruleId: 'IAC-K8S-003',
          title: 'Montagem de Volume no Sistema de Arquivos do Host (hostPath)',
          category: 'KUBERNETES',
          severity: 'HIGH',
          file: file.path,
          line: 1,
          snippet: 'volumes:\n  - hostPath: path: /',
          description: 'Montar diretórios raiz do host em pods permite que um container comprometido leia ou modifique arquivos sensíveis do nó hospedeiro.',
          remediation: 'Substitua volumes hostPath por PersistentVolumeClaims (PVC) gerenciados.',
          compliance: { cisBenchmark: 'CIS Kubernetes 5.2.4' }
        });
      }
    }

    // ==========================================
    // 4. CI/CD & GitHub Actions Audits
    // ==========================================
    if (filePath.includes('.github/workflows') || filePath.includes('.gitlab-ci')) {
      totalFilesScanned++;
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        const lineNum = idx + 1;

        if (trimmed.includes('pull_request_target:')) {
          findings.push({
            id: `iac-gha-target-${idx}`,
            ruleId: 'IAC-GHA-001',
            title: 'Uso Inseguro de pull_request_target com Acesso de Escrita',
            category: 'CICD',
            severity: 'CRITICAL',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'O gatilho pull_request_target executa com os secrets do repositório base. Se fizer checkout do código do fork sem cautela, atacantes podem exfiltrar credenciais de produção.',
            remediation: 'Utilize o evento `pull_request` padrão com permissões de leitura ou use isolamento com `workflow_run`.',
            compliance: { nist: 'NIST SSDF PO.3.1' }
          });
        }

        if (/\$\{\{\s*github\.event\.pull_request\.(title|body|head\.ref)\s*\}\}/.test(trimmed)) {
          findings.push({
            id: `iac-gha-injection-${idx}`,
            ruleId: 'IAC-GHA-002',
            title: 'Potencial Injeção de Comandos em Scripts do GitHub Actions',
            category: 'CICD',
            severity: 'HIGH',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'Interpolar variáveis controladas por atacantes (como título de PR ou branch) diretamente dentro de blocos `run:` permite injeção arbitrária de comandos bash.',
            remediation: 'Passe o valor como uma variável de ambiente intermediária (ex: `env: PR_TITLE: ${{ github.event... }}`) e referencie `$PR_TITLE`.',
            compliance: { cisBenchmark: 'CIS GitHub Actions 2.3' }
          });
        }
      });
    }

    // ==========================================
    // 5. Terraform Audits
    // ==========================================
    if (fileName.endsWith('.tf') || fileName.endsWith('.tfvars')) {
      totalFilesScanned++;
      lines.forEach((line, idx) => {
        const trimmed = line.trim();
        const lineNum = idx + 1;

        if (trimmed.includes('cidr_blocks = ["0.0.0.0/0"]') && (file.content.includes('22') || file.content.includes('3389'))) {
          findings.push({
            id: `iac-tf-sg-${idx}`,
            ruleId: 'IAC-TF-001',
            title: 'Security Group Permite Acesso SSH/RDP de Qualquer IP (0.0.0.0/0)',
            category: 'TERRAFORM',
            severity: 'HIGH',
            file: file.path,
            line: lineNum,
            snippet: line,
            description: 'Permitir entrada irrestrita na porta 22 ou 3389 a partir de toda a internet expõe a infraestrutura a ataques de força bruta e exploração zero-day.',
            remediation: 'Restrinja o acesso ao CIDR da VPN corporativa ou use AWS SSM / Cloudflare Tunnels.',
            compliance: { cisBenchmark: 'CIS AWS Foundations 4.1' }
          });
        }
      });
    }
  }

  const passedChecks = Math.max(0, 15 - findings.length);
  const failedChecks = findings.length;
  const criticalDeduction = findings.filter(f => f.severity === 'CRITICAL').length * 20;
  const highDeduction = findings.filter(f => f.severity === 'HIGH').length * 10;
  const mediumDeduction = findings.filter(f => f.severity === 'MEDIUM').length * 5;
  const iacPostureScore = Math.max(10, Math.min(100, 100 - (criticalDeduction + highDeduction + mediumDeduction)));

  const summaryByTech = {
    DOCKER: {
      count: findings.filter(f => f.category === 'DOCKER').length,
      critical: findings.filter(f => f.category === 'DOCKER' && f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.category === 'DOCKER' && f.severity === 'HIGH').length
    },
    KUBERNETES: {
      count: findings.filter(f => f.category === 'KUBERNETES').length,
      critical: findings.filter(f => f.category === 'KUBERNETES' && f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.category === 'KUBERNETES' && f.severity === 'HIGH').length
    },
    TERRAFORM: {
      count: findings.filter(f => f.category === 'TERRAFORM').length,
      critical: findings.filter(f => f.category === 'TERRAFORM' && f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.category === 'TERRAFORM' && f.severity === 'HIGH').length
    },
    COMPOSE: {
      count: findings.filter(f => f.category === 'COMPOSE').length,
      critical: findings.filter(f => f.category === 'COMPOSE' && f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.category === 'COMPOSE' && f.severity === 'HIGH').length
    },
    CICD: {
      count: findings.filter(f => f.category === 'CICD').length,
      critical: findings.filter(f => f.category === 'CICD' && f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.category === 'CICD' && f.severity === 'HIGH').length
    }
  };

  return {
    totalFilesScanned: Math.max(totalFilesScanned, 1),
    passedChecks,
    failedChecks,
    iacPostureScore,
    findings,
    summaryByTech
  };
}
