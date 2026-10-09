import { ScanFinding, ThreatActorProfile, OtxPulse, ThreatIntelFeedStatus } from '../types';
import { INITIAL_OTX_PULSES, THREAT_ACTOR_PROFILES } from './cyberThreatIntelEngine';

export interface CtiVectorDefinition {
  id: string;
  key: string;
  name: string;
  namePt: string;
  nameEn: string;
  descriptionPt: string;
  descriptionEn: string;
  mitreTtp: string;
  cisaKevCves: string[];
  cisaKevActive: boolean;
  otxPulseId: string;
  primaryCategory: string;
  remediationAdvicePt: string;
  remediationAdviceEn: string;
}

export const CTI_VECTORS: CtiVectorDefinition[] = [
  {
    id: 'VEC_CLOUD_IAM',
    key: 'CLOUD_IAM',
    name: 'Cloud Credentials & AWS IAM',
    namePt: 'Credenciais de Nuvem & AWS IAM',
    nameEn: 'Cloud Credentials & AWS IAM',
    descriptionPt: 'Chaves de acesso permanente (AKIA), credenciais STS e segredos de nuvem com acesso irrestrito a recursos corporativos.',
    descriptionEn: 'Permanent access keys (AKIA), STS credentials, and cloud secrets granting unrestricted access to enterprise infrastructure.',
    mitreTtp: 'T1552.001 (Credentials in Files) / T1580 (Cloud Discovery)',
    cisaKevCves: ['CVE-2024-21626', 'CVE-2023-48795'],
    cisaKevActive: true,
    otxPulseId: 'pulse-otx-2026-9042',
    primaryCategory: 'CLOUD_CREDENTIAL',
    remediationAdvicePt: 'Revogar imediatamente credenciais IAM expostas, migrar para AWS IAM Roles com OIDC temporário e aplicar princípio de menor privilégio.',
    remediationAdviceEn: 'Immediately revoke exposed IAM keys, transition to temporary OIDC IAM roles, and enforce least-privilege policies.'
  },
  {
    id: 'VEC_SSH_KEYS',
    key: 'SSH_KEYS',
    name: 'SSH & Private Cryptographic Keys',
    namePt: 'Chaves SSH & Certificados Privados',
    nameEn: 'SSH & Private Cryptographic Keys',
    descriptionPt: 'Pares de chaves privadas (id_rsa, PEM, PKCS#8) expostos em commits, permitindo movimentação lateral e bypass de MFA.',
    descriptionEn: 'Private key pairs (id_rsa, PEM, PKCS#8) exposed in source repositories, facilitating lateral movement and MFA bypass.',
    mitreTtp: 'T1552.004 (Private Keys id_rsa) / T1078 (Valid Accounts)',
    cisaKevCves: ['CVE-2024-23897'],
    cisaKevActive: true,
    otxPulseId: 'pulse-otx-2026-7833',
    primaryCategory: 'PRIVATE_KEY',
    remediationAdvicePt: 'Substituir chaves RSA por SSH Certificates de curta duração, rotacionar chaves de servidores e implementar git-secrets no hook de pré-commit.',
    remediationAdviceEn: 'Replace static RSA keys with short-lived SSH certificates, rotate server keys, and enforce pre-commit git-secrets hooks.'
  },
  {
    id: 'VEC_DATABASE',
    key: 'DATABASE',
    name: 'Database Connection URIs & Secrets',
    namePt: 'Strings de Conexão & Credenciais de Banco',
    nameEn: 'Database Connection URIs & Secrets',
    descriptionPt: 'URIs de conexão com senhas em texto plano para Postgres, MongoDB, MySQL e Redis, alvo prioritário de exfiltração para ransomware.',
    descriptionEn: 'Connection strings with plaintext credentials for PostgreSQL, MongoDB, MySQL, and Redis, targeted for double-extortion dumps.',
    mitreTtp: 'T1486 (Data Encrypted for Impact) / T1552.001 (Credentials in Repositories)',
    cisaKevCves: ['CVE-2026-2189'],
    cisaKevActive: true,
    otxPulseId: 'pulse-cisa-kev-2026-01',
    primaryCategory: 'DATABASE_URI',
    remediationAdvicePt: 'Externalizar URIs de conexão para cofre de segredos (Vault/AWS Secrets Manager), rotacionar credenciais e isolar portas de banco.',
    remediationAdviceEn: 'Externalize database URIs to secret managers (Vault/AWS Secrets Manager), rotate credentials, and block public DB access.'
  },
  {
    id: 'VEC_AUTH_JWT',
    key: 'AUTH_JWT',
    name: 'Stateless Auth Tokens & Payment Keys',
    namePt: 'Tokens JWT & Chaves de Pagamento',
    nameEn: 'Stateless Auth Tokens & Payment Keys',
    descriptionPt: 'Assinaturas JWT vulneráveis a bypass de algoritmo (alg:none), segredos fracos de assinatura HMAC e chaves de API financeiras (Stripe).',
    descriptionEn: 'JWT signatures vulnerable to algorithm confusion (alg:none), weak HMAC signing keys, and financial API keys (Stripe/Braintree).',
    mitreTtp: 'T1078 (Valid Token Forgery) / T1553.002 (Code Signing Abuse)',
    cisaKevCves: ['CVE-2022-21449'],
    cisaKevActive: false,
    otxPulseId: 'pulse-misp-2026-8812',
    primaryCategory: 'AUTH_TOKEN',
    remediationAdvicePt: 'Rejeitar rigorosamente tokens com alg:none, adotar chaves assimétricas RS256 com rotação de JWKS e isolar chaves de produção de gateway.',
    remediationAdviceEn: 'Strictly reject alg:none tokens, adopt RS256 asymmetric keys with JWKS rotation, and isolate gateway production keys.'
  },
  {
    id: 'VEC_SSRF_IMDS',
    key: 'SSRF_IMDS',
    name: 'SSRF & Cloud Metadata (IMDSv1)',
    namePt: 'SSRF & Serviço de Metadados (IMDSv1)',
    nameEn: 'SSRF & Cloud Metadata (IMDSv1)',
    descriptionPt: 'Manipulação de requisições do servidor para consultar o endereço 169.254.169.254 e exfiltrar tokens de serviço de instâncias EC2/GCE.',
    descriptionEn: 'Server-side request forgery targeting 169.254.169.254 to harvest temporary cloud instance profile credentials and tokens.',
    mitreTtp: 'T1552.005 (Cloud Instance Metadata Service) / T1190 (Exploit Public App)',
    cisaKevCves: ['CVE-2026-2189', 'CVE-2024-23897'],
    cisaKevActive: true,
    otxPulseId: 'pulse-cisa-kev-2026-01',
    primaryCategory: 'SSRF',
    remediationAdvicePt: 'Migrar instâncias para IMDSv2 com hop-limit de 1 token obrigatório e implementar listas seguras estritas para chamadas HTTP externas.',
    remediationAdviceEn: 'Enforce IMDSv2 token requirement with hop-limit 1 and apply strict allowlists for outbound HTTP requests.'
  },
  {
    id: 'VEC_SUPPLY_CHAIN',
    key: 'SUPPLY_CHAIN',
    name: 'Software Supply Chain & npm Packages',
    namePt: 'Cadeia de Suprimentos & Pacotes npm',
    nameEn: 'Software Supply Chain & npm Packages',
    descriptionPt: 'Dependências de software comprometidas, typosquatting de registros públicos e scripts maliciosos de preinstall/postinstall em repositórios.',
    descriptionEn: 'Compromised dependencies, open source typosquatting, and malicious preinstall/postinstall build scripts in repositories.',
    mitreTtp: 'T1195.001 (Compromise Software Dependencies) / T1059.007 (JavaScript Execution)',
    cisaKevCves: ['CVE-2023-38039'],
    cisaKevActive: true,
    otxPulseId: 'pulse-otx-2026-7833',
    primaryCategory: 'SUPPLY_CHAIN',
    remediationAdvicePt: 'Bloquear execução de scripts arbitrários no npm (`--ignore-scripts`), auditar package-lock.json e gerar SBOM automatizado no CI/CD.',
    remediationAdviceEn: 'Block arbitrary npm script execution (`--ignore-scripts`), audit lockfiles, and generate automated SBOM in CI/CD pipelines.'
  },
  {
    id: 'VEC_WEB_EXPLOIT',
    key: 'WEB_EXPLOIT',
    name: 'Public Web Injections & Endpoints',
    namePt: 'Injeções Web & Endpoints Públicos',
    nameEn: 'Public Web Injections & Endpoints',
    descriptionPt: 'Vulnerabilidades em aplicações expostas (SQL Injection, Command Injection, BOLA) usadas como vetor primário de intrusão inicial.',
    descriptionEn: 'Vulnerabilities in public-facing applications (SQL Injection, Command Injection, BOLA) leveraged for initial foothold.',
    mitreTtp: 'T1190 (Exploit Public-Facing Application) / T1059.004 (Unix Shell)',
    cisaKevCves: ['CVE-2024-3400'],
    cisaKevActive: true,
    otxPulseId: 'pulse-misp-2026-8812',
    primaryCategory: 'INJECTION',
    remediationAdvicePt: 'Adotar consultas preparadas parametrizadas, sanitização rigorosa de entradas de usuário e validação com WAF em modo bloqueio.',
    remediationAdviceEn: 'Adopt parameterized queries, rigorous input sanitization, and deploy WAF in active blocking mode.'
  },
  {
    id: 'VEC_CONTAINER_EDGE',
    key: 'CONTAINER_EDGE',
    name: 'Container Sockets & Edge Infrastructure',
    namePt: 'Sockets de Contêiner & Infraestrutura Edge',
    nameEn: 'Container Sockets & Edge Infrastructure',
    descriptionPt: 'Sockets Docker expostos sem autenticação (porta 2375), permissões de container privilegiado e portas de gerenciamento sem firewall.',
    descriptionEn: 'Exposed Docker daemons without TLS (port 2375), privileged containers, and unprotected edge gateway management ports.',
    mitreTtp: 'T1613 (Container Discovery) / T1496 (Resource Hijacking Cryptojacking)',
    cisaKevCves: ['CVE-2024-21626'],
    cisaKevActive: true,
    otxPulseId: 'pulse-cisa-kev-2026-01',
    primaryCategory: 'CONTAINER',
    remediationAdvicePt: 'Nunca expor `/var/run/docker.sock`, rodar contêineres como usuário não-root (rootless mode) e habilitar auditoria de runtime via Falco.',
    remediationAdviceEn: 'Never mount docker.sock into untrusted containers, run rootless containers, and enforce runtime audit with Falco.'
  }
];

// Global baseline activity pattern scores per Actor × Vector (Extracted from CISA KEV & OTX Feeds)
// Scale: 0 to 100
export const ACTOR_VECTOR_GLOBAL_ACTIVITY: Record<string, Record<string, number>> = {
  'actor-scattered-spider': {
    VEC_CLOUD_IAM: 98,
    VEC_AUTH_JWT: 92,
    VEC_SSH_KEYS: 74,
    VEC_SSRF_IMDS: 80,
    VEC_DATABASE: 64,
    VEC_SUPPLY_CHAIN: 60,
    VEC_WEB_EXPLOIT: 70,
    VEC_CONTAINER_EDGE: 66
  },
  'actor-lazarus-group': {
    VEC_SUPPLY_CHAIN: 99,
    VEC_SSH_KEYS: 96,
    VEC_DATABASE: 91,
    VEC_CLOUD_IAM: 82,
    VEC_WEB_EXPLOIT: 88,
    VEC_AUTH_JWT: 84,
    VEC_SSRF_IMDS: 70,
    VEC_CONTAINER_EDGE: 72
  },
  'actor-volt-typhoon': {
    VEC_SSH_KEYS: 95,
    VEC_CONTAINER_EDGE: 94,
    VEC_WEB_EXPLOIT: 92,
    VEC_CLOUD_IAM: 78,
    VEC_SSRF_IMDS: 76,
    VEC_DATABASE: 70,
    VEC_AUTH_JWT: 65,
    VEC_SUPPLY_CHAIN: 62
  },
  'actor-fin7': {
    VEC_AUTH_JWT: 96,
    VEC_WEB_EXPLOIT: 94,
    VEC_DATABASE: 88,
    VEC_CLOUD_IAM: 80,
    VEC_SSH_KEYS: 72,
    VEC_SUPPLY_CHAIN: 68,
    VEC_SSRF_IMDS: 60,
    VEC_CONTAINER_EDGE: 55
  },
  'actor-lockbit-syndicate': {
    VEC_DATABASE: 98,
    VEC_CLOUD_IAM: 90,
    VEC_SSH_KEYS: 86,
    VEC_CONTAINER_EDGE: 82,
    VEC_WEB_EXPLOIT: 80,
    VEC_SSRF_IMDS: 78,
    VEC_AUTH_JWT: 70,
    VEC_SUPPLY_CHAIN: 65
  },
  'actor-teamtnt': {
    VEC_SSRF_IMDS: 97,
    VEC_CONTAINER_EDGE: 96,
    VEC_CLOUD_IAM: 91,
    VEC_SSH_KEYS: 85,
    VEC_DATABASE: 74,
    VEC_WEB_EXPLOIT: 78,
    VEC_SUPPLY_CHAIN: 60,
    VEC_AUTH_JWT: 58
  }
};

export type HeatmapOverlayTier =
  | 'CRITICAL_OVERLAY'  // Findings detected + High Actor Pattern + CISA KEV (Pulsing Red)
  | 'HIGH_OVERLAY'      // Findings detected + Elevated Actor Pattern (Vivid Orange)
  | 'MODERATE_OVERLAY'  // Findings detected + Moderate Actor Pattern (Amber)
  | 'GLOBAL_HIGH'       // No findings detected, but Global Feed Activity is High/Targeted (Subtle Cyan/Blue)
  | 'GLOBAL_BASELINE';  // Baseline activity (Dark Muted)

export interface CtiHeatmapCellData {
  actorId: string;
  actor: ThreatActorProfile;
  vectorId: string;
  vector: CtiVectorDefinition;
  globalActivityScore: number; // 0 - 100
  detectedCount: number;
  matchedFindings: ScanFinding[];
  intensity: number; // 0 - 100 overlay score
  tier: HeatmapOverlayTier;
  riskMultiplier: number;
  isCisaKevExploited: boolean;
  otxPulse?: OtxPulse;
  topTtp: string;
  threatSummary: string;
}

export interface CtiHeatmapSummary {
  cells: CtiHeatmapCellData[];
  totalOverlayFindings: number;
  criticalHotspotsCount: number;
  highHotspotsCount: number;
  cisaKevOverlapsCount: number;
  highestRiskActor: ThreatActorProfile;
  highestRiskVector: CtiVectorDefinition;
  averageIntensity: number;
  actors: ThreatActorProfile[];
  vectors: CtiVectorDefinition[];
}

/**
 * Matches a scan finding to one or more CTI Vectors based on rule attributes and keywords.
 */
export function matchFindingToVectors(finding: ScanFinding): string[] {
  const matchedVectorIds: string[] = [];
  const text = `${finding.category} ${finding.ruleName} ${finding.file} ${finding.matchedSecret || ''} ${finding.description}`.toLowerCase();

  // Cloud IAM
  if (
    finding.category === 'CLOUD_CREDENTIAL' ||
    text.includes('aws') ||
    text.includes('akia') ||
    text.includes('s3') ||
    text.includes('iam') ||
    text.includes('azure') ||
    text.includes('google_cloud') ||
    text.includes('gcp')
  ) {
    matchedVectorIds.push('VEC_CLOUD_IAM');
  }

  // SSH & Private Keys
  if (
    finding.category === 'PRIVATE_KEY' ||
    text.includes('id_rsa') ||
    text.includes('private key') ||
    text.includes('ssh') ||
    text.includes('-----begin') ||
    text.includes('openssh') ||
    text.includes('cert')
  ) {
    matchedVectorIds.push('VEC_SSH_KEYS');
  }

  // Database Connection Strings
  if (
    finding.category === 'DATABASE_URI' ||
    finding.category === 'PASSWORD' ||
    text.includes('postgres') ||
    text.includes('mysql') ||
    text.includes('mongo') ||
    text.includes('redis') ||
    text.includes('database_url') ||
    text.includes('db_pass')
  ) {
    matchedVectorIds.push('VEC_DATABASE');
  }

  // Auth & JWT
  if (
    finding.category === 'AUTH_TOKEN' ||
    text.includes('jwt') ||
    text.includes('bearer') ||
    text.includes('stripe') ||
    text.includes('sk_live') ||
    text.includes('alg:none') ||
    text.includes('token')
  ) {
    matchedVectorIds.push('VEC_AUTH_JWT');
  }

  // SSRF & IMDSv1
  if (
    text.includes('ssrf') ||
    text.includes('169.254.169.254') ||
    text.includes('metadata') ||
    text.includes('imds') ||
    text.includes('webhook') ||
    text.includes('internal ip')
  ) {
    matchedVectorIds.push('VEC_SSRF_IMDS');
  }

  // Supply Chain
  if (
    text.includes('npm') ||
    text.includes('package.json') ||
    text.includes('dependency') ||
    text.includes('supply chain') ||
    text.includes('lockfile') ||
    text.includes('pypi')
  ) {
    matchedVectorIds.push('VEC_SUPPLY_CHAIN');
  }

  // Web Injection
  if (
    text.includes('injection') ||
    text.includes('sqli') ||
    text.includes('command') ||
    text.includes('eval') ||
    text.includes('xss') ||
    text.includes('payload')
  ) {
    matchedVectorIds.push('VEC_WEB_EXPLOIT');
  }

  // Container & Edge
  if (
    text.includes('docker') ||
    text.includes('container') ||
    text.includes('k8s') ||
    text.includes('kubernetes') ||
    text.includes('port 2375') ||
    text.includes('socket')
  ) {
    matchedVectorIds.push('VEC_CONTAINER_EDGE');
  }

  // Fallback: If no vector matched directly, categorize based on severity
  if (matchedVectorIds.length === 0) {
    if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
      matchedVectorIds.push('VEC_WEB_EXPLOIT');
    } else {
      matchedVectorIds.push('VEC_CLOUD_IAM');
    }
  }

  return matchedVectorIds;
}

/**
 * Computes the complete 2D heatmap matrix overlaying detected workspace findings
 * with global threat actor activity patterns from CISA KEV and AlienVault OTX feeds.
 */
export function computeCtiHeatmapMatrix(
  findings: ScanFinding[] = [],
  actors: ThreatActorProfile[] = THREAT_ACTOR_PROFILES,
  pulses: OtxPulse[] = INITIAL_OTX_PULSES,
  vectors: CtiVectorDefinition[] = CTI_VECTORS
): CtiHeatmapSummary {
  // Map findings to vectors
  const findingsByVector: Record<string, ScanFinding[]> = {};
  vectors.forEach(v => {
    findingsByVector[v.id] = [];
  });

  findings.forEach(f => {
    const matchedVectorIds = matchFindingToVectors(f);
    matchedVectorIds.forEach(vId => {
      if (findingsByVector[vId]) {
        findingsByVector[vId].push(f);
      }
    });
  });

  const cells: CtiHeatmapCellData[] = [];
  let totalOverlayFindings = 0;
  let criticalHotspots = 0;
  let highHotspots = 0;
  let cisaKevOverlaps = 0;

  actors.forEach(actor => {
    vectors.forEach(vector => {
      const globalActivity = ACTOR_VECTOR_GLOBAL_ACTIVITY[actor.id]?.[vector.id] ?? 70;
      const matched = findingsByVector[vector.id] || [];
      const count = matched.length;

      const hasCritical = matched.some(f => f.severity === 'CRITICAL');
      const hasHigh = matched.some(f => f.severity === 'HIGH');
      const isCisaKev = vector.cisaKevActive || matched.some(f => f.threatIntelTag?.cisaKevExploited);

      let intensity = 0;
      let tier: HeatmapOverlayTier = 'GLOBAL_BASELINE';
      let multiplier = 1.0;

      if (count > 0) {
        // ACTIVE OVERLAY: Detected Vulnerability in workspace meets Actor's targeted vector
        totalOverlayFindings += count;
        multiplier = 1.25 + (globalActivity / 100) * 0.5 + (isCisaKev ? 0.25 : 0);
        multiplier = Math.round(multiplier * 100) / 100;

        // Calculate heat intensity: 0 to 100
        const baseScore = globalActivity * 0.45;
        const findingBoost = Math.min(30, count * 10);
        const severityBoost = hasCritical ? 25 : hasHigh ? 15 : 8;
        const cisaKevBoost = isCisaKev ? 15 : 0;

        intensity = Math.min(100, Math.round(baseScore + findingBoost + severityBoost + cisaKevBoost));

        if (intensity >= 80 || (hasCritical && isCisaKev)) {
          tier = 'CRITICAL_OVERLAY';
          criticalHotspots++;
          if (isCisaKev) cisaKevOverlaps++;
        } else if (intensity >= 60) {
          tier = 'HIGH_OVERLAY';
          highHotspots++;
          if (isCisaKev) cisaKevOverlaps++;
        } else {
          tier = 'MODERATE_OVERLAY';
        }
      } else {
        // BACKGROUND PATTERN: No detected vulnerability in this specific vector,
        // but global threat feeds show actor activity.
        intensity = Math.round(globalActivity * 0.32); // subtle background range ~20-32%
        multiplier = 1.0;

        if (globalActivity >= 90) {
          tier = 'GLOBAL_HIGH';
        } else {
          tier = 'GLOBAL_BASELINE';
        }
      }

      // Find matching OTX Pulse
      const matchingPulse = pulses.find(p => p.id === vector.otxPulseId || p.adversary?.includes(actor.name));

      // Top TTP
      const matchingActorTtp = actor.ttps.find(t =>
        vector.mitreTtp.toLowerCase().includes(t.techniqueId.toLowerCase())
      );
      const topTtp = matchingActorTtp
        ? `${matchingActorTtp.techniqueId} - ${matchingActorTtp.name}`
        : vector.mitreTtp.split('/')[0].trim();

      const threatSummary = count > 0
        ? `ALERTA CRÍTICO: ${count} vulnerabilidade(s) detectada(s) no workspace alinham-se diretamente aos padrões de invasão do ator ${actor.name} (${actor.codeName}). Vetor: ${vector.name}.`
        : `Padrão de inteligência global: O ator ${actor.name} mantém alta atividade no vetor ${vector.name}. Nenhum achado correspondente no workspace atual.`;

      cells.push({
        actorId: actor.id,
        actor,
        vectorId: vector.id,
        vector,
        globalActivityScore: globalActivity,
        detectedCount: count,
        matchedFindings: matched,
        intensity,
        tier,
        riskMultiplier: multiplier,
        isCisaKevExploited: isCisaKev && count > 0,
        otxPulse: matchingPulse,
        topTtp,
        threatSummary
      });
    });
  });

  // Determine highest risk actor
  const actorRiskScores = actors.map(actor => {
    const actorCells = cells.filter(c => c.actorId === actor.id && c.detectedCount > 0);
    const score = actorCells.reduce((acc, c) => acc + c.intensity * c.riskMultiplier, 0);
    return { actor, score };
  }).sort((a, b) => b.score - a.score);

  const highestRiskActor = actorRiskScores[0]?.actor || actors[0];

  // Determine highest risk vector
  const vectorRiskScores = vectors.map(vector => {
    const vectorCells = cells.filter(c => c.vectorId === vector.id && c.detectedCount > 0);
    const score = vectorCells.reduce((acc, c) => acc + c.intensity * c.riskMultiplier, 0);
    return { vector, score };
  }).sort((a, b) => b.score - a.score);

  const highestRiskVector = vectorRiskScores[0]?.vector || vectors[0];

  const avgIntensity = cells.length > 0
    ? Math.round(cells.reduce((acc, c) => acc + c.intensity, 0) / cells.length)
    : 0;

  return {
    cells,
    totalOverlayFindings,
    criticalHotspotsCount: criticalHotspots,
    highHotspotsCount: highHotspots,
    cisaKevOverlapsCount: cisaKevOverlaps,
    highestRiskActor,
    highestRiskVector,
    averageIntensity: avgIntensity,
    actors,
    vectors
  };
}
