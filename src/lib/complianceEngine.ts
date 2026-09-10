import {
  ScanFinding,
  ComplianceFrameworkId,
  ComplianceControlDefinition,
  EvaluatedComplianceControl,
  FrameworkReadinessSummary,
  GlobalComplianceAssessment,
  ComplianceControlStatus
} from '../types';

export const COMPLIANCE_FRAMEWORKS_META: Record<
  ComplianceFrameworkId,
  { name: string; badge: string; description: string; color: string; docUrl: string }
> = {
  SOC2: {
    name: 'SOC 2 Type II',
    badge: 'AICPA TSC',
    description: 'Critérios de Confiança e Segurança (Trust Services Criteria) para proteção de credenciais e integridade de sistemas.',
    color: '#3366FF',
    docUrl: 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustanalyticsservices.html',
  },
  HIPAA: {
    name: 'HIPAA Security Rule',
    badge: '45 CFR § 164',
    description: 'Normas federais para proteção de dados eletrônicos de saúde (ePHI), controle estrito de acesso e criptografia.',
    color: '#00F0FF',
    docUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  },
  OWASP_TOP_10: {
    name: 'OWASP Top 10:2021',
    badge: 'OWASP Foundation',
    description: 'Padrão global de conscientização sobre as 10 vulnerabilidades mais críticas em segurança de aplicações web.',
    color: '#FF3E00',
    docUrl: 'https://owasp.org/Top10/',
  },
  PCI_DSS: {
    name: 'PCI-DSS v4.0',
    badge: 'PCI SSC',
    description: 'Padrão de Segurança de Dados da Indústria de Cartões de Pagamento para proteção de chaves e segredos em código.',
    color: '#EAB308',
    docUrl: 'https://www.pcisecuritystandards.org/',
  },
  ISO_27001: {
    name: 'ISO/IEC 27001:2022',
    badge: 'ISO Annex A',
    description: 'Sistema de Gestão de Segurança da Informação (SGSI), cobrindo codificação segura e gestão de criptografia.',
    color: '#A855F7',
    docUrl: 'https://www.iso.org/standard/27001',
  },
};

export const COMPLIANCE_CONTROLS_CATALOG: ComplianceControlDefinition[] = [
  // ==================== SOC 2 TYPE II ====================
  {
    id: 'soc2-cc6-1',
    framework: 'SOC2',
    frameworkName: 'SOC 2 Type II',
    code: 'CC6.1',
    title: 'Logical Access Controls & Authentication Secrets',
    category: 'Acesso Lógico & Identidade',
    description: 'A organização implementa controles de acesso lógico sobre dados de infraestrutura e impede credenciais de autenticação estáticas em repositórios.',
    auditImplication: 'Apontamento de Deficiência em auditorias SOC 2 Type II. Segredos estáticos violam a segregação de deveres e o princípio de privilégio mínimo.',
    recommendedRemediation: 'Remover credenciais do código, rotacionar chaves expostas e adotar OAuth 2.0 / tokens efêmeros via IAM.',
    severityThreshold: 'HIGH',
    matchingCategories: ['AUTH_TOKEN', 'API_KEY', 'PASSWORD'],
    matchingKeywords: ['token', 'api key', 'jwt', 'auth', 'bearer', 'github', 'slack'],
    docUrl: 'https://www.aicpa.org/trustservices',
  },
  {
    id: 'soc2-cc6-6',
    framework: 'SOC2',
    frameworkName: 'SOC 2 Type II',
    code: 'CC6.6',
    title: 'Boundary Protection & Cloud Infrastructure Secrets',
    category: 'Proteção de Fronteiras & Nuvem',
    description: 'Proteção de fronteiras lógicas da infraestrutura de nuvem, impedindo o vazamento de chaves de acesso administrativo a buckets e clusters.',
    auditImplication: 'Falha grave no controle de fronteiras. O acesso direto à nuvem por chaves embutidas expõe o perímetro de segurança a invasões externas.',
    recommendedRemediation: 'Injetar credenciais exclusivamente em runtime via AWS Secrets Manager, GCP Secret Manager ou Vault.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['CLOUD_CREDENTIAL', 'DATABASE_URI'],
    matchingKeywords: ['aws', 'google', 'azure', 'cloud', 's3', 'bucket', 'gcs', 'db_url', 'postgres'],
    docUrl: 'https://www.aicpa.org/trustservices',
  },
  {
    id: 'soc2-cc6-7',
    framework: 'SOC2',
    frameworkName: 'SOC 2 Type II',
    code: 'CC6.7',
    title: 'Data Transmission & Cryptographic Key Separation',
    category: 'Criptografia & Chaves Privadas',
    description: 'Proteção da transmissão de dados e salvaguarda das chaves criptográficas privadas (RSA, SSH, PGP, certificados SSL).',
    auditImplication: 'Comprometimento direto da confidencialidade dos dados do cliente. Chaves privadas em código descredenciam a criptografia em repouso/trânsito.',
    recommendedRemediation: 'Substituir chaves privadas por HSM (Hardware Security Module) ou KMS (Key Management Service) gerenciado.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['PRIVATE_KEY'],
    matchingKeywords: ['rsa', 'ssh', 'private key', 'certificate', 'pem', 'pgp'],
    docUrl: 'https://www.aicpa.org/trustservices',
  },
  {
    id: 'soc2-cc7-1',
    framework: 'SOC2',
    frameworkName: 'SOC 2 Type II',
    code: 'CC7.1',
    title: 'Vulnerability Detection & Code Security Management',
    category: 'Gestão de Vulnerabilidades',
    description: 'Processos automatizados para detectar e mitigar vulnerabilidades e fluxos de injeção no código antes da implantação em produção.',
    auditImplication: 'Auditores avaliam evidências de varreduras SAST contínuas no pipeline. A existência de sinks não sanitizados evidencia falha do processo.',
    recommendedRemediation: 'Corrigir fluxos de entrada inseguros, eliminar execuções com eval()/innerHTML e habilitar Quality Gates no CI/CD.',
    severityThreshold: 'MEDIUM',
    matchingCategories: ['TAINT_SINK', 'CUSTOM_REGEX', 'ENTROPY'],
    matchingKeywords: ['sink', 'eval', 'innerhtml', 'entropy', 'taint', 'xss'],
    docUrl: 'https://www.aicpa.org/trustservices',
  },

  // ==================== HIPAA SECURITY RULE ====================
  {
    id: 'hipaa-164-312-a1',
    framework: 'HIPAA',
    frameworkName: 'HIPAA Security Rule',
    code: '§ 164.312(a)(1)',
    title: 'Access Control & ePHI Data Safeguards',
    category: 'Controle de Acesso Técnico',
    description: 'Implementação de mecanismos técnicos que permitam apenas que pessoas ou softwares autorizados acessem sistemas com dados de saúde (ePHI).',
    auditImplication: 'Violação com multas pesadas pelo HHS Office for Civil Rights (OCR). Chaves ou tokens estáticos facilitam o acesso irrestrito a prontuários.',
    recommendedRemediation: 'Implementar autenticação federada com MFA e segregação estrita por função (RBAC).',
    severityThreshold: 'HIGH',
    matchingCategories: ['AUTH_TOKEN', 'API_KEY', 'PASSWORD'],
    matchingKeywords: ['token', 'auth', 'health', 'patient', 'phi', 'key'],
    docUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  },
  {
    id: 'hipaa-164-312-e1',
    framework: 'HIPAA',
    frameworkName: 'HIPAA Security Rule',
    code: '§ 164.312(e)(1)',
    title: 'Transmission Security & Encrypted Communications',
    category: 'Segurança em Trânsito',
    description: 'Garantia de que conexões entre aplicações cliente e servidores que manipulam ePHI sejam blindadas contra interceptação não autorizada.',
    auditImplication: 'Endpoints de API sem criptografia ou expostos em código estático permitem ataques de Man-in-the-Middle e exfiltração de ePHI.',
    recommendedRemediation: 'Forçar HTTPS/TLS 1.3 obrigatório em todos os endpoints e utilizar tokens JWT assinados com chaves assimétricas seguras.',
    severityThreshold: 'HIGH',
    matchingCategories: ['CLOUD_CREDENTIAL', 'API_PATH', 'DATABASE_URI'],
    matchingKeywords: ['api', 'http', 'cloud', 'database', 'endpoint', 'transmission'],
    docUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  },
  {
    id: 'hipaa-164-308-a1',
    framework: 'HIPAA',
    frameworkName: 'HIPAA Security Rule',
    code: '§ 164.308(a)(1)(ii)(B)',
    title: 'Risk Management & Credential Sprawl Mitigation',
    category: 'Gestão Administrativa de Riscos',
    description: 'Aplicação contínua de medidas de segurança que reduzam riscos e vulnerabilidades a um nível razoável e apropriado em todo o código.',
    auditImplication: 'Auditorias do HHS exigem um plano de avaliação de risco formal comprovando que segredos não estão distribuídos em artefatos de build.',
    recommendedRemediation: 'Instituir varreduras SAST bloqueantes em Pull Requests e políticas formais de ciclo de vida de credenciais.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['CLOUD_CREDENTIAL', 'PRIVATE_KEY', 'ENTROPY'],
    matchingKeywords: ['risk', 'secret', 'sprawl', 'cloud', 'key'],
    docUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  },
  {
    id: 'hipaa-164-312-c1',
    framework: 'HIPAA',
    frameworkName: 'HIPAA Security Rule',
    code: '§ 164.312(c)(1)',
    title: 'ePHI Data Integrity & Injection Prevention',
    category: 'Integridade de Dados',
    description: 'Políticas e controles para proteger prontuários eletrônicos contra alteração imprópria ou destruição não autorizada por injeções de código.',
    auditImplication: 'Vulnerabilidades de injeção ou acesso direto ao banco de dados violam os requisitos de integridade irrefutável do prontuário.',
    recommendedRemediation: 'Utilizar ORMs parametrizados, sanitizadores contra XSS/DOM injection e proibir strings de conexão com usuário root/admin no código.',
    severityThreshold: 'HIGH',
    matchingCategories: ['DATABASE_URI', 'TAINT_SINK'],
    matchingKeywords: ['db', 'sql', 'postgres', 'mongo', 'sink', 'integrity', 'injection'],
    docUrl: 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  },

  // ==================== OWASP TOP 10:2021 ====================
  {
    id: 'owasp-a01',
    framework: 'OWASP_TOP_10',
    frameworkName: 'OWASP Top 10:2021',
    code: 'A01:2021',
    title: 'Broken Access Control (Quebra de Controle de Acesso)',
    category: 'Controle de Acesso',
    description: 'Falhas que permitem que usuários ajam fora de suas permissões pretendidas, como exposição de rotas administrativas e tokens reutilizáveis.',
    auditImplication: 'Classificado como o Risco #1 em aplicações web modernas. Permite visualização e modificação não autorizada de dados.',
    recommendedRemediation: 'Negar acesso por padrão (deny-by-default), implementar checagens de autorização no servidor e invalidar tokens expostos.',
    severityThreshold: 'HIGH',
    matchingCategories: ['AUTH_TOKEN', 'API_PATH', 'API_KEY'],
    matchingKeywords: ['access', 'token', 'admin', 'auth', 'endpoint', 'path'],
    docUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
  },
  {
    id: 'owasp-a02',
    framework: 'OWASP_TOP_10',
    frameworkName: 'OWASP Top 10:2021',
    code: 'A02:2021',
    title: 'Cryptographic Failures (Falhas Criptográficas)',
    category: 'Criptografia & Segredos',
    description: 'Exposição de segredos sensíveis em texto claro no código, uso de algoritmos fracos ou vazamento de chaves privadas e certificados.',
    auditImplication: 'Causa primordial de vazamentos maciços de dados e comprometimento de contas em nuvem corporativa.',
    recommendedRemediation: 'Criptografar dados sensíveis, remover chaves estáticas do código e usar algoritmos modernos com gerenciador de chaves.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['PRIVATE_KEY', 'CLOUD_CREDENTIAL', 'DATABASE_URI', 'PASSWORD', 'ENTROPY'],
    matchingKeywords: ['crypto', 'secret', 'rsa', 'private', 'password', 'entropy', 'key'],
    docUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
  },
  {
    id: 'owasp-a03',
    framework: 'OWASP_TOP_10',
    frameworkName: 'OWASP Top 10:2021',
    code: 'A03:2021',
    title: 'Injection & Dangerous Sinks (Injeção de Código)',
    category: 'Injeção',
    description: 'Dados não confiáveis são enviados ao interpretador como parte de um comando ou consulta (DOM XSS, eval, innerHTML, document.write).',
    auditImplication: 'Permite execução arbitrária de scripts no navegador da vítima, roubo de cookies de sessão e redirecionamento malicioso.',
    recommendedRemediation: 'Usar APIs seguras como textContent, templates com escape automático e bibliotecas como DOMPurify.',
    severityThreshold: 'HIGH',
    matchingCategories: ['TAINT_SINK'],
    matchingKeywords: ['sink', 'eval', 'innerhtml', 'injection', 'xss'],
    docUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
  },
  {
    id: 'owasp-a05',
    framework: 'OWASP_TOP_10',
    frameworkName: 'OWASP Top 10:2021',
    code: 'A05:2021',
    title: 'Security Misconfiguration (Configuração Insegura)',
    category: 'Configuração Insegura',
    description: 'Configurações padrão ativadas, buckets de nuvem públicos, exposição de credenciais em arquivos .env commitados no repositório.',
    auditImplication: 'Portas de entrada abertas que facilitam a descoberta automatizada de infraestrutura por atacantes externos.',
    recommendedRemediation: 'Implementar processos de hardening automatizados, excluir arquivos de ambiente do Git via .gitignore e restringir permissões de buckets.',
    severityThreshold: 'HIGH',
    matchingCategories: ['CLOUD_CREDENTIAL', 'DATABASE_URI', 'CUSTOM_REGEX'],
    matchingKeywords: ['config', 'bucket', 'env', 'database', 'misconfiguration'],
    docUrl: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
  },
  {
    id: 'owasp-a07',
    framework: 'OWASP_TOP_10',
    frameworkName: 'OWASP Top 10:2021',
    code: 'A07:2021',
    title: 'Identification and Authentication Failures (Falhas de Autenticação)',
    category: 'Autenticação & Identidade',
    description: 'Confirmação incorreta da identidade do usuário, senhas hardcoded, chaves de API estáticas e ausência de rotação.',
    auditImplication: 'Permite que invasores assumam identidades de serviços de nuvem ou usuários com privilégios administrativos.',
    recommendedRemediation: 'Eliminar senhas no código, exigir autenticação multifator (MFA) e adotar rotação periódica automática de credenciais.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['API_KEY', 'PASSWORD', 'AUTH_TOKEN'],
    matchingKeywords: ['auth', 'password', 'api key', 'jwt', 'credential', 'login'],
    docUrl: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
  },

  // ==================== PCI-DSS v4.0 ====================
  {
    id: 'pci-req-3-5',
    framework: 'PCI_DSS',
    frameworkName: 'PCI-DSS v4.0',
    code: 'Req 3.5',
    title: 'Protect Cryptographic Keys Used for Cardholder Data',
    category: 'Proteção de Chaves Criptográficas',
    description: 'Chaves criptográficas utilizadas para proteger dados de cartões de pagamento devem ser protegidas contra divulgação e jamais embutidas em código.',
    auditImplication: 'Reprovação imediata pelo assessor QSA. Exige plano de remediação emergencial para manter a certificação de processamento de pagamentos.',
    recommendedRemediation: 'Armazenar chaves em módulos HSM ou serviços de KMS em conformidade FIPS 140-2 Nível 3.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['PRIVATE_KEY', 'CLOUD_CREDENTIAL'],
    matchingKeywords: ['key', 'rsa', 'pci', 'crypto', 'card', 'payment'],
    docUrl: 'https://www.pcisecuritystandards.org/',
  },
  {
    id: 'pci-req-6-3',
    framework: 'PCI_DSS',
    frameworkName: 'PCI-DSS v4.0',
    code: 'Req 6.3',
    title: 'Secure Software Development & Secret Elimination',
    category: 'Desenvolvimento Seguro de Software',
    description: 'Todo software customizado é desenvolvido de forma segura, com revisões automatizadas de código contra segredos e vulnerabilidades conhecidas.',
    auditImplication: 'Exigência mandante de SAST em pipelines de CI/CD para organizações que processam ou transmitem dados de cartões.',
    recommendedRemediation: 'Integrar scanners SAST no fluxo de pull requests com bloqueio automático de merges que contenham segredos.',
    severityThreshold: 'HIGH',
    matchingCategories: ['AUTH_TOKEN', 'API_KEY', 'PASSWORD', 'DATABASE_URI', 'TAINT_SINK'],
    matchingKeywords: ['software', 'code', 'sast', 'ci-cd', 'secret', 'sink'],
    docUrl: 'https://www.pcisecuritystandards.org/',
  },
  {
    id: 'pci-req-8-2',
    framework: 'PCI_DSS',
    frameworkName: 'PCI-DSS v4.0',
    code: 'Req 8.2',
    title: 'User & System Authentication Credential Management',
    category: 'Gestão de Credenciais de Usuários e Sistemas',
    description: 'Políticas estritas para identificação e autenticação de contas de sistema e administrativas; proibição de senhas hardcoded em scripts.',
    auditImplication: 'Apontamento grave de não conformidade no Relatório de Conformidade (ROC).',
    recommendedRemediation: 'Substituir senhas fixas por certificados gerenciados, contas de serviço sem chaves estáticas e identidades de carga de trabalho.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['PASSWORD', 'AUTH_TOKEN', 'API_KEY'],
    matchingKeywords: ['password', 'credential', 'auth', 'user', 'secret'],
    docUrl: 'https://www.pcisecuritystandards.org/',
  },

  // ==================== ISO/IEC 27001:2022 ====================
  {
    id: 'iso-a-8-9',
    framework: 'ISO_27001',
    frameworkName: 'ISO/IEC 27001:2022',
    code: 'A.8.9',
    title: 'Configuration Management (Gestão de Configuração)',
    category: 'Configuração Segura',
    description: 'Configurações de segurança de software e infraestrutura são estabelecidas, documentadas e monitoradas contra desvios não autorizados.',
    auditImplication: 'Não conformidade em auditorias de certificação ISO 27001 por organismo certificador credenciado.',
    recommendedRemediation: 'Centralizar configurações em repositórios controlados com versionamento e variáveis de ambiente validadas no build.',
    severityThreshold: 'HIGH',
    matchingCategories: ['DATABASE_URI', 'CLOUD_CREDENTIAL', 'CUSTOM_REGEX'],
    matchingKeywords: ['config', 'database', 'cloud', 'environment'],
    docUrl: 'https://www.iso.org/standard/27001',
  },
  {
    id: 'iso-a-8-24',
    framework: 'ISO_27001',
    frameworkName: 'ISO/IEC 27001:2022',
    code: 'A.8.24',
    title: 'Use of Cryptography & Key Lifecycle Governance',
    category: 'Governança Criptográfica',
    description: 'Regras para o uso eficaz de criptografia e gestão de chaves durante todo o seu ciclo de vida (geração, armazenamento e descarte).',
    auditImplication: 'Violação formal da política corporativa de segurança da informação e confidencialidade de ativos.',
    recommendedRemediation: 'Implementar procedimento operacional padrão para rotação de chaves e destruição de credenciais depreciadas.',
    severityThreshold: 'CRITICAL',
    matchingCategories: ['PRIVATE_KEY', 'AUTH_TOKEN', 'ENTROPY'],
    matchingKeywords: ['crypto', 'key', 'rsa', 'entropy', 'token'],
    docUrl: 'https://www.iso.org/standard/27001',
  },
  {
    id: 'iso-a-8-28',
    framework: 'ISO_27001',
    frameworkName: 'ISO/IEC 27001:2022',
    code: 'A.8.28',
    title: 'Secure Coding Principles (Codificação Segura)',
    category: 'Desenvolvimento Seguro',
    description: 'Princípios de codificação segura aplicados ao desenvolvimento de software para prevenir vulnerabilidades de código e vazamento de segredos.',
    auditImplication: 'Requisito mandatório introduzido na revisão ISO 27001:2022 exigindo evidências práticas de validação de código.',
    recommendedRemediation: 'Adotar diretrizes de codificação segura (OWASP/Snyk), treinamentos para desenvolvedores e bloqueio preventivo de vulnerabilidades.',
    severityThreshold: 'HIGH',
    matchingCategories: ['TAINT_SINK', 'API_KEY', 'PASSWORD', 'CLOUD_CREDENTIAL'],
    matchingKeywords: ['secure coding', 'code', 'sast', 'sink', 'secret'],
    docUrl: 'https://www.iso.org/standard/27001',
  },
];

/**
 * Checks if a scan finding matches a compliance control
 */
export function matchFindingToControl(finding: ScanFinding, control: ComplianceControlDefinition): boolean {
  if (finding.isFalsePositive) return false;

  // 1. Direct Category Match
  if (control.matchingCategories.includes(finding.category)) {
    return true;
  }

  // 2. Rule ID match
  if (control.matchingRuleIds && control.matchingRuleIds.includes(finding.ruleId)) {
    return true;
  }

  // 3. Keyword match in rule name, file path or snippet
  if (control.matchingKeywords && control.matchingKeywords.length > 0) {
    const textTarget = `${finding.ruleName} ${finding.file} ${finding.description} ${finding.category}`.toLowerCase();
    const hasKeyword = control.matchingKeywords.some((kw) => textTarget.includes(kw.toLowerCase()));
    if (hasKeyword) return true;
  }

  return false;
}

/**
 * Evaluates the full compliance readiness posture across all standards
 */
export function evaluateComplianceReadiness(findings: ScanFinding[]): GlobalComplianceAssessment {
  const activeFindings = (findings || []).filter((f) => !f.isFalsePositive);

  // Evaluate each control
  const evaluatedControls: EvaluatedComplianceControl[] = COMPLIANCE_CONTROLS_CATALOG.map((control) => {
    const matched = activeFindings.filter((finding) => matchFindingToControl(finding, control));

    const criticalCount = matched.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = matched.filter((f) => f.severity === 'HIGH').length;
    const mediumCount = matched.filter((f) => f.severity === 'MEDIUM').length;
    const lowCount = matched.filter((f) => f.severity === 'LOW' || f.severity === 'INFO').length;

    // Calculate risk points
    const riskPoints = criticalCount * 25 + highCount * 15 + mediumCount * 7 + lowCount * 2;

    // Determine status
    let status: ComplianceControlStatus = 'COMPLIANT';
    if (criticalCount > 0 || highCount > 0 || matched.length >= 3) {
      status = 'AT_RISK';
    } else if (matched.length > 0) {
      status = 'DEGRADED';
    }

    return {
      ...control,
      status,
      matchingFindings: matched,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      riskPoints,
    };
  });

  // Calculate summaries per framework
  const frameworksList: ComplianceFrameworkId[] = ['SOC2', 'HIPAA', 'OWASP_TOP_10', 'PCI_DSS', 'ISO_27001'];
  const frameworkSummaries = {} as Record<ComplianceFrameworkId, FrameworkReadinessSummary>;

  let totalControlsAtRisk = 0;
  let totalControlsDegraded = 0;
  let totalControlsCompliant = 0;
  let frameworksAtRiskCount = 0;

  frameworksList.forEach((fwKey) => {
    const fwMeta = COMPLIANCE_FRAMEWORKS_META[fwKey];
    const fwControls = evaluatedControls.filter((c) => c.framework === fwKey);
    const total = fwControls.length;

    const atRisk = fwControls.filter((c) => c.status === 'AT_RISK').length;
    const degraded = fwControls.filter((c) => c.status === 'DEGRADED').length;
    const compliant = fwControls.filter((c) => c.status === 'COMPLIANT').length;

    totalControlsAtRisk += atRisk;
    totalControlsDegraded += degraded;
    totalControlsCompliant += compliant;

    // Unique violating findings for this framework
    const violatingFindingsIds = new Set<string>();
    fwControls.forEach((c) => c.matchingFindings.forEach((f) => violatingFindingsIds.add(f.id)));

    // Readiness calculation:
    // Compliant controls count as 100%, Degraded as 50%, At Risk as 0%
    const readinessPercentage = total > 0 
      ? Math.max(0, Math.round(((compliant * 1.0 + degraded * 0.5) / total) * 100))
      : 100;

    let status: ComplianceControlStatus = 'COMPLIANT';
    if (atRisk > 0) {
      status = 'AT_RISK';
      frameworksAtRiskCount++;
    } else if (degraded > 0) {
      status = 'DEGRADED';
    }

    frameworkSummaries[fwKey] = {
      framework: fwKey,
      name: fwMeta.name,
      badge: fwMeta.badge,
      shortDescription: fwMeta.description,
      totalControls: total,
      compliantControls: compliant,
      atRiskControls: atRisk,
      degradedControls: degraded,
      readinessPercentage,
      status,
      violatingFindingsCount: violatingFindingsIds.size,
    };
  });

  const totalControls = evaluatedControls.length;
  const overallReadinessPercentage = totalControls > 0
    ? Math.max(0, Math.round(((totalControlsCompliant * 1.0 + totalControlsDegraded * 0.5) / totalControls) * 100))
    : 100;

  let overallStatus: ComplianceControlStatus = 'COMPLIANT';
  if (totalControlsAtRisk > 0) {
    overallStatus = 'AT_RISK';
  } else if (totalControlsDegraded > 0) {
    overallStatus = 'DEGRADED';
  }

  return {
    overallReadinessPercentage,
    overallStatus,
    totalControlsEvaluated: totalControls,
    totalControlsAtRisk,
    totalControlsDegraded,
    totalControlsCompliant,
    frameworksAtRiskCount,
    totalFrameworksCount: frameworksList.length,
    frameworkSummaries,
    evaluatedControls,
  };
}

/**
 * Generates an executive Markdown audit report ready for export
 */
export function generateComplianceMarkdownReport(assessment: GlobalComplianceAssessment): string {
  const dateStr = new Date().toISOString().split('T')[0];
  let md = `# RELATÓRIO DE PRONTIDÃO DE CONFORMIDADE & SAST (COMPLIANCE READINESS AUDIT)\n`;
  md += `**Data da Avaliação:** ${dateStr} | **Status Geral:** ${assessment.overallStatus}\n`;
  md += `**Índice de Prontidão Global:** ${assessment.overallReadinessPercentage}% | **Padrões em Risco:** ${assessment.frameworksAtRiskCount} de ${assessment.totalFrameworksCount}\n\n`;

  md += `## 1. RESUMO EXECUTIVO POR FRAMEWORK\n\n`;
  md += `| Framework | Status | Prontidão (%) | Controles em Risco | Controles Conformes | Achados SAST |\n`;
  md += `| :--- | :---: | :---: | :---: | :---: | :---: |\n`;

  Object.values(assessment.frameworkSummaries).forEach((fw) => {
    md += `| **${fw.name}** | ${fw.status} | ${fw.readinessPercentage}% | ${fw.atRiskControls} / ${fw.totalControls} | ${fw.compliantControls} | ${fw.violatingFindingsCount} |\n`;
  });

  md += `\n## 2. DETALHAMENTO DE PADRÕES EM RISCO & CONTROLES COMPROMETIDOS\n\n`;
  assessment.evaluatedControls
    .filter((c) => c.status !== 'COMPLIANT')
    .forEach((ctrl) => {
      md += `### [${ctrl.status}] ${ctrl.frameworkName} • ${ctrl.code}: ${ctrl.title}\n`;
      md += `- **Impacto na Auditoria:** ${ctrl.auditImplication}\n`;
      md += `- **Recomendação de Remediação:** ${ctrl.recommendedRemediation}\n`;
      md += `- **Achados de SAST Associados (${ctrl.matchingFindings.length}):**\n`;
      ctrl.matchingFindings.forEach((f) => {
        md += `  - **[${f.severity}]** \`${f.ruleName}\` em \`${f.file}:${f.line}\` (Segredo: \`${f.maskedSecret}\`)\n`;
      });
      md += `\n`;
    });

  return md;
}
