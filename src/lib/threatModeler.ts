import { ScanFinding, ApiEndpointFinding } from '../types';

export type StrideCategory = 
  | 'SPOOFING' 
  | 'TAMPERING' 
  | 'REPUDIATION' 
  | 'INFORMATION_DISCLOSURE' 
  | 'DENIAL_OF_SERVICE' 
  | 'ELEVATION_OF_PRIVILEGE';

export interface StrideThreatItem {
  id: string;
  category: StrideCategory;
  title: string;
  threatDescription: string;
  affectedAsset: string;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitigationStatus: 'UNMITIGATED' | 'PARTIALLY_MITIGATED' | 'MITIGATED';
  recommendedCountermeasure: string;
  sourceFindingId?: string;
}

export interface AsvsChapterRequirement {
  chapterId: string;
  chapterName: string;
  level: 'L1' | 'L2' | 'L3';
  description: string;
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'NEEDS_REVIEW';
  findingCount: number;
  verificationGuidance: string;
}

export interface CvssMetrics {
  attackVector: 'NETWORK' | 'ADJACENT' | 'LOCAL' | 'PHYSICAL';
  attackComplexity: 'LOW' | 'HIGH';
  privilegesRequired: 'NONE' | 'LOW' | 'HIGH';
  userInteraction: 'NONE' | 'REQUIRED';
  scope: 'UNCHANGED' | 'CHANGED';
  confidentiality: 'NONE' | 'LOW' | 'HIGH';
  integrity: 'NONE' | 'LOW' | 'HIGH';
  availability: 'NONE' | 'LOW' | 'HIGH';
}

export interface CvssScoreResult {
  baseScore: number;
  severityRating: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  vectorString: string;
  impactSubScore: number;
  exploitabilitySubScore: number;
}

/**
 * Calculates CVSS v3.1 Base Score per FIRST.org official specification
 */
export function calculateCvssScore(metrics: CvssMetrics): CvssScoreResult {
  const avWeights = { NETWORK: 0.85, ADJACENT: 0.62, LOCAL: 0.55, PHYSICAL: 0.2 };
  const acWeights = { LOW: 0.77, HIGH: 0.44 };
  const prWeightsUnchanged = { NONE: 0.85, LOW: 0.62, HIGH: 0.27 };
  const prWeightsChanged = { NONE: 0.85, LOW: 0.68, HIGH: 0.50 };
  const uiWeights = { NONE: 0.85, REQUIRED: 0.62 };
  const cWeights = { NONE: 0.0, LOW: 0.22, HIGH: 0.56 };
  const iWeights = { NONE: 0.0, LOW: 0.22, HIGH: 0.56 };
  const aWeights = { NONE: 0.0, LOW: 0.22, HIGH: 0.56 };

  const av = avWeights[metrics.attackVector];
  const ac = acWeights[metrics.attackComplexity];
  const pr = metrics.scope === 'CHANGED' ? prWeightsChanged[metrics.privilegesRequired] : prWeightsUnchanged[metrics.privilegesRequired];
  const ui = uiWeights[metrics.userInteraction];

  const exploitability = 8.22 * av * ac * pr * ui;

  const c = cWeights[metrics.confidentiality];
  const i = iWeights[metrics.integrity];
  const a = aWeights[metrics.availability];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  let impact: number;
  if (metrics.scope === 'UNCHANGED') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  let baseScore = 0;
  if (impact > 0) {
    if (metrics.scope === 'UNCHANGED') {
      baseScore = Math.min(10, Math.ceil(Math.min(impact + exploitability, 10) * 10) / 10);
    } else {
      baseScore = Math.min(10, Math.ceil(Math.min(1.08 * (impact + exploitability), 10) * 10) / 10);
    }
  }

  let severityRating: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'NONE';
  if (baseScore >= 9.0) severityRating = 'CRITICAL';
  else if (baseScore >= 7.0) severityRating = 'HIGH';
  else if (baseScore >= 4.0) severityRating = 'MEDIUM';
  else if (baseScore > 0.0) severityRating = 'LOW';

  const vectorString = `CVSS:3.1/AV:${metrics.attackVector[0]}/AC:${metrics.attackComplexity[0]}/PR:${metrics.privilegesRequired[0]}/UI:${metrics.userInteraction[0]}/S:${metrics.scope[0]}/C:${metrics.confidentiality[0]}/I:${metrics.integrity[0]}/A:${metrics.availability[0]}`;

  return {
    baseScore: Number(baseScore.toFixed(1)),
    severityRating,
    vectorString,
    impactSubScore: Number(impact.toFixed(1)),
    exploitabilitySubScore: Number(exploitability.toFixed(1))
  };
}

export function buildThreatModelFromWorkspace(
  findings: ScanFinding[],
  endpoints: ApiEndpointFinding[]
): {
  strideThreats: StrideThreatItem[];
  asvsRequirements: AsvsChapterRequirement[];
  compliancePercentage: number;
} {
  const strideThreats: StrideThreatItem[] = [];

  // Map Findings to STRIDE Categories
  for (const f of findings) {
    if (f.ruleName.includes('Token') || f.ruleName.includes('JWT') || f.ruleName.includes('Key')) {
      strideThreats.push({
        id: `stride-spoof-${f.id}`,
        category: 'SPOOFING',
        title: `Impersonação de Identidade via Token Vazado (${f.ruleName})`,
        threatDescription: `Atacantes podem usar a credencial hardcoded encontrada em ${f.file} para forjar requisições autenticadas.`,
        affectedAsset: f.file,
        riskLevel: f.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        mitigationStatus: 'UNMITIGATED',
        recommendedCountermeasure: 'Revogar chave, rotacionar credenciais e migrar para AWS Secrets Manager / Vault.',
        sourceFindingId: f.id
      });
    }

    if ((f.category as string) === 'DANGEROUS_EVAL' || f.ruleName.includes('HTML') || f.snippet.includes('eval(')) {
      strideThreats.push({
        id: `stride-tamp-${f.id}`,
        category: 'TAMPERING',
        title: `Adulteração de Execução de Código em Tempo de Execução`,
        threatDescription: `Injeção maliciosa em evaluators ou sinks perigosos de DOM no arquivo ${f.file}.`,
        affectedAsset: f.file,
        riskLevel: 'CRITICAL',
        mitigationStatus: 'UNMITIGATED',
        recommendedCountermeasure: 'Substituir eval por parsers tipados estritamente e sanitizar inputs com DOMPurify.',
        sourceFindingId: f.id
      });
    }

    strideThreats.push({
      id: `stride-infodisc-${f.id}`,
      category: 'INFORMATION_DISCLOSURE',
      title: `Vazamento de Dados Confidenciais em ${f.file}`,
      threatDescription: `A presença de segredos em texto claro expõe ativos da organização para qualquer leitor do repositório.`,
      affectedAsset: f.file,
      riskLevel: f.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      mitigationStatus: 'UNMITIGATED',
      recommendedCountermeasure: 'Auditar permissões de acesso ao repositório e executar scrubbing de histórico git.',
      sourceFindingId: f.id
    });
  }

  // Endpoints threat modeling
  for (const ep of endpoints) {
    if (ep.isInternalOrAdmin || ep.path.includes('admin') || ep.path.includes('refunds')) {
      strideThreats.push({
        id: `stride-elev-${ep.id}`,
        category: 'ELEVATION_OF_PRIVILEGE',
        title: `Escalação de Privilégios em Rota Administrativa (${ep.path})`,
        threatDescription: `O endpoint administrativo ${ep.path} foi descoberto em ${ep.file}. Caso não exija RBAC estrito, usuários comuns podem disparar ações com privilégios de superusuário.`,
        affectedAsset: ep.path,
        riskLevel: 'HIGH',
        mitigationStatus: 'PARTIALLY_MITIGATED',
        recommendedCountermeasure: 'Implementar middleware de autorização por função (RBAC) com verificação de escopo de claims.'
      });
    }

    if (ep.path.includes('audit-trail') || ep.path.includes('metrics')) {
      strideThreats.push({
        id: `stride-repud-${ep.id}`,
        category: 'REPUDIATION',
        title: `Integridade e Não-Repúdio da Trilha de Auditoria`,
        threatDescription: `Falhas na proteção do endpoint ${ep.path} podem permitir exclusão ou falsificação de logs forenses.`,
        affectedAsset: ep.path,
        riskLevel: 'MEDIUM',
        mitigationStatus: 'MITIGATED',
        recommendedCountermeasure: 'Assinar logs com hash encadeado (Write-Once-Read-Many) e enviar para SIEM externo.'
      });
    }
  }

  // OWASP ASVS v4.0.3 Chapter Mapping
  const asvsRequirements: AsvsChapterRequirement[] = [
    {
      chapterId: 'V1',
      chapterName: 'Arquitetura e Modelagem de Ameaças',
      level: 'L1',
      description: 'Verificar se todos os componentes do sistema têm modelagem de ameaças e fronteiras de confiança definidas.',
      status: strideThreats.length > 0 ? 'NEEDS_REVIEW' : 'COMPLIANT',
      findingCount: strideThreats.length,
      verificationGuidance: 'Documentar zonas desmilitarizadas (DMZ) e barreiras de confiança entre microserviços.'
    },
    {
      chapterId: 'V2',
      chapterName: 'Autenticação e Gestão de Credenciais',
      level: 'L1',
      description: 'Garantir que senhas e chaves de API não estejam embutidas no código-fonte.',
      status: findings.length > 0 ? 'NON_COMPLIANT' : 'COMPLIANT',
      findingCount: findings.length,
      verificationGuidance: 'Exigir autenticação multifator (MFA) e rotação de segredos via Vault.'
    },
    {
      chapterId: 'V4',
      chapterName: 'Controle de Acesso (RBAC/ABAC)',
      level: 'L2',
      description: 'Verificar se endpoints administrativos aplicam o princípio do menor privilégio.',
      status: endpoints.some(e => e.isInternalOrAdmin) ? 'NEEDS_REVIEW' : 'COMPLIANT',
      findingCount: endpoints.filter(e => e.isInternalOrAdmin).length,
      verificationGuidance: 'Assegurar que todas as chamadas verifiquem contexto de sessão e papéis autorizados.'
    },
    {
      chapterId: 'V5',
      chapterName: 'Validação e Sanitização de Entradas',
      level: 'L1',
      description: 'Validar dados de entrada através de listas permitidas estritas antes de alimentar sinks e queries.',
      status: findings.some(f => (f.category as string) === 'DANGEROUS_EVAL' || f.ruleName.includes('eval') || f.ruleName.includes('HTML')) ? 'NON_COMPLIANT' : 'COMPLIANT',
      findingCount: findings.filter(f => (f.category as string) === 'DANGEROUS_EVAL' || f.ruleName.includes('eval') || f.ruleName.includes('HTML')).length,
      verificationGuidance: 'Utilizar bibliotecas de validação de schemas (ex: Zod, Joi) e queries parametrizadas.'
    },
    {
      chapterId: 'V8',
      chapterName: 'Criptografia e Proteção de Dados',
      level: 'L2',
      description: 'Garantir criptografia robusta em trânsito (TLS 1.3) e repouso (AES-GCM com chaves seguras).',
      status: 'COMPLIANT',
      findingCount: 0,
      verificationGuidance: 'Utilizar TLS moderno e desabilitar suites legadas (SSLv3, TLS 1.0/1.1).'
    },
    {
      chapterId: 'V14',
      chapterName: 'Configuração Segura de Infraestrutura',
      level: 'L1',
      description: 'Containers e servidores não devem executar como superusuário root.',
      status: findings.length > 0 ? 'NEEDS_REVIEW' : 'COMPLIANT',
      findingCount: findings.length > 0 ? 2 : 0,
      verificationGuidance: 'Aplicar CIS Benchmarks para Docker e Kubernetes.'
    }
  ];

  const compliantCount = asvsRequirements.filter(r => r.status === 'COMPLIANT').length;
  const compliancePercentage = Math.round((compliantCount / asvsRequirements.length) * 100);

  return {
    strideThreats,
    asvsRequirements,
    compliancePercentage
  };
}
