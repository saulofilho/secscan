import {
  IamAuditReport,
  IamPolicyFinding,
  IamRiskLevel
} from '../types/securityTools';

export const SAMPLE_IAM_POLICIES: { name: string; description: string; json: string }[] = [
  {
    name: 'Administrador Overprivileged (Wildcard Total)',
    description: 'Concede Action: "*" em Resource: "*", violando diretamente o princípio de privilégio mínimo.',
    json: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "AllowEverythingWildcard",
          Effect: "Allow",
          Action: "*",
          Resource: "*"
        }
      ]
    }, null, 2)
  },
  {
    name: 'Privilege Escalation via iam:PassRole & Lambda',
    description: 'Permite criar funções Lambda e repassar qualquer role IAM, permitindo ao invasor assumir permissões de Admin.',
    json: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "LambdaDeployerRole",
          Effect: "Allow",
          Action: [
            "lambda:CreateFunction",
            "lambda:InvokeFunction",
            "iam:PassRole"
          ],
          Resource: "*"
        }
      ]
    }, null, 2)
  },
  {
    name: 'Bucket S3 de Dados Sensíveis com Acesso Público',
    description: 'Política de bucket com Principal "*" permitindo que qualquer pessoa na internet leia e delete objetos.',
    json: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "PublicReadWriteAccess",
          Effect: "Allow",
          Principal: "*",
          Action: [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"
          ],
          Resource: "arn:aws:s3:::empresa-financeira-data-lake/*"
        }
      ]
    }, null, 2)
  },
  {
    name: 'Leitura Estrita S3 e DynamoDB (Hardened)',
    description: 'Acesso estrito de leitura a recursos delimitados com restrição de IP e TLS obrigatório.',
    json: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "StrictSecureReadAccess",
          Effect: "Allow",
          Action: [
            "s3:GetObject",
            "dynamodb:GetItem",
            "dynamodb:Query"
          ],
          Resource: [
            "arn:aws:s3:::empresa-reports/2026/*",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Clients"
          ],
          Condition: {
            Bool: {
              "aws:SecureTransport": "true"
            }
          }
        }
      ]
    }, null, 2)
  }
];

// Dangerous AWS IAM Action pairs known for Privilege Escalation
const ESCALATION_VECTORS: { actions: string[]; title: string; desc: string; cwe: string }[] = [
  {
    actions: ['iam:passrole', 'lambda:createfunction'],
    title: 'Escalada de Privilégio: iam:PassRole + lambda:CreateFunction',
    desc: 'Permite criar uma função Lambda com uma role administrativa e executá-la para roubar credenciais do host.',
    cwe: 'CWE-250'
  },
  {
    actions: ['iam:passrole', 'ec2:runinstances'],
    title: 'Escalada de Privilégio: iam:PassRole + ec2:RunInstances',
    desc: 'Permite lançar uma instância EC2 anexada a uma role de privilégio elevado e ler seus tokens de instância via IMDS.',
    cwe: 'CWE-250'
  },
  {
    actions: ['iam:createpolicyversion'],
    title: 'Escalada de Privilégio: iam:CreatePolicyVersion Direto',
    desc: 'Permite que o usuário crie uma nova versão de uma política gerenciada e a configure como versão padrão, adicionando Admin.',
    cwe: 'CWE-269'
  },
  {
    actions: ['iam:setdefaultpolicyversion'],
    title: 'Escalada de Privilégio: iam:SetDefaultPolicyVersion',
    desc: 'Permite ativar versões anteriores de políticas que possam ter privilégios mais amplos.',
    cwe: 'CWE-269'
  },
  {
    actions: ['iam:attachuserpolicy'],
    title: 'Escalada de Privilégio: iam:AttachUserPolicy',
    desc: 'Permite anexar diretamente a política AdministratorAccess ao próprio usuário.',
    cwe: 'CWE-269'
  },
  {
    actions: ['iam:attachrolepolicy'],
    title: 'Escalada de Privilégio: iam:AttachRolePolicy',
    desc: 'Permite adicionar políticas de super-administrador a qualquer role existente no ambiente.',
    cwe: 'CWE-269'
  }
];

export function auditIamPolicy(policyString: string, policyName: string = 'AWS-IAM-Policy'): IamAuditReport {
  let parsed: any;
  try {
    parsed = JSON.parse(policyString);
  } catch (err) {
    return {
      policyName,
      riskScore: 0,
      posture: 'NON_COMPLIANT',
      findings: [
        {
          id: 'iam-json-syntax-err',
          title: 'Erro de Sintaxe JSON na Política IAM',
          severity: 'CRITICAL',
          category: 'CREDENTIAL_EXPOSURE',
          affectedStatementIndex: 0,
          affectedActionOrResource: 'JSON_SYNTAX',
          description: 'O texto fornecido não é um JSON válido. Políticas inválidas não são aceitas pela AWS.',
          attackVector: 'Falha de configuração do CloudFormation/Terraform.',
          remediation: 'Corrija as chaves e vírgulas da estrutura JSON.',
          cwe: 'CWE-20',
          benchmark: 'AWS IAM Policy Grammar'
        }
      ],
      wildcardActionsDetected: [],
      wildcardResourcesDetected: [],
      privilegeEscalationVectors: [],
      leastPrivilegePolicySnippet: '// Erro de sintaxe no JSON'
    };
  }

  const statements: any[] = Array.isArray(parsed.Statement) ? parsed.Statement : [parsed.Statement].filter(Boolean);
  const findings: IamPolicyFinding[] = [];
  const wildcardActionsDetected: string[] = [];
  const wildcardResourcesDetected: string[] = [];
  const privilegeEscalationVectors: string[] = [];

  const allAllowedActions: string[] = [];

  statements.forEach((stmt, sIdx) => {
    if (stmt.Effect !== 'Allow') return;

    // Check Principal: "*" (Bucket policy risk)
    if (stmt.Principal === '*' || (stmt.Principal && stmt.Principal.AWS === '*')) {
      findings.push({
        id: `iam-public-principal-${sIdx}`,
        title: 'Exposição Pública: Principal "*" Detectado',
        severity: 'CRITICAL',
        category: 'PUBLIC_EXPOSURE',
        affectedStatementIndex: sIdx,
        affectedActionOrResource: 'Principal: *',
        description: 'A política permite acesso para qualquer usuário ou conta anônima da internet.',
        attackVector: 'Ataque externo irrestrito sem necessidade de autenticação AWS.',
        remediation: 'Restrinja o Principal para ARNs específicos de contas ou adicione condições de aws:PrincipalOrgID.',
        cwe: 'CWE-284',
        benchmark: 'AWS CIS Benchmark 2.1.5'
      });
    }

    // Normalize Actions
    const actions: string[] = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action].filter(Boolean);
    actions.forEach(act => {
      allAllowedActions.push(act.toLowerCase());
      if (act === '*') {
        wildcardActionsDetected.push(`Statement[${sIdx}]: *`);
        findings.push({
          id: `iam-wildcard-action-${sIdx}`,
          title: 'Ação Totalmente Aberta (Action: "*")',
          severity: 'CRITICAL',
          category: 'WILDCARD_ACTION',
          affectedStatementIndex: sIdx,
          affectedActionOrResource: act,
          description: 'A política concede todas as ações de todas as APIs da AWS, concedendo privilégios de Super Administrador.',
          attackVector: 'Comprometimento total da infraestrutura em nuvem caso a credencial seja exfiltrada.',
          remediation: 'Substitua o curinga "*" pela lista estrita de ações necessárias (ex: s3:GetObject, dynamodb:GetItem).',
          cwe: 'CWE-250',
          benchmark: 'AWS CIS Benchmark 1.16'
        });
      } else if (act.endsWith(':*')) {
        wildcardActionsDetected.push(`Statement[${sIdx}]: ${act}`);
        findings.push({
          id: `iam-wildcard-service-${sIdx}-${act}`,
          title: `Ação Curinga no Serviço (${act})`,
          severity: 'HIGH',
          category: 'WILDCARD_ACTION',
          affectedStatementIndex: sIdx,
          affectedActionOrResource: act,
          description: `Permite todas as operações dentro do serviço ${act.split(':')[0]}, incluindo comandos destrutivos de deleção.`,
          attackVector: 'Deleção ou exfiltração em massa de recursos do serviço.',
          remediation: `Restrinja para verbos específicos como Describe*, Get*, Put*.`,
          cwe: 'CWE-732',
          benchmark: 'NIST 800-53 AC-6'
        });
      }
    });

    // Normalize Resources
    const resources: string[] = Array.isArray(stmt.Resource) ? stmt.Resource : [stmt.Resource].filter(Boolean);
    resources.forEach(res => {
      if (res === '*') {
        wildcardResourcesDetected.push(`Statement[${sIdx}]: *`);
        findings.push({
          id: `iam-wildcard-res-${sIdx}`,
          title: 'Recurso Sem Escopo (Resource: "*")',
          severity: 'HIGH',
          category: 'WILDCARD_RESOURCE',
          affectedStatementIndex: sIdx,
          affectedActionOrResource: res,
          description: 'As ações permitidas podem ser executadas em absolutamente qualquer recurso da conta AWS.',
          attackVector: 'Movimentação lateral entre recursos não relacionados.',
          remediation: 'Especifique o ARN exato do bucket, tabela DynamoDB, instância ou fila SQS.',
          cwe: 'CWE-732',
          benchmark: 'AWS Well-Architected Security Pillar'
        });
      }
    });

    // Check for SecureTransport (SSL/TLS requirement)
    if (!stmt.Condition || !stmt.Condition.Bool || stmt.Condition.Bool['aws:SecureTransport'] !== 'true') {
      if (actions.some(a => a.toLowerCase().startsWith('s3:'))) {
        findings.push({
          id: `iam-missing-tls-${sIdx}`,
          title: 'Falta de Imposição de HTTPS/TLS (aws:SecureTransport)',
          severity: 'LOW',
          category: 'CREDENTIAL_EXPOSURE',
          affectedStatementIndex: sIdx,
          affectedActionOrResource: 'Condition: aws:SecureTransport',
          description: 'A política do bucket não exige que requisições ocorram estritamente sobre HTTPS criptografado.',
          attackVector: 'Interceptação de dados em trânsito (Man-in-the-Middle).',
          remediation: 'Adicione a condição {"Bool": {"aws:SecureTransport": "true"}}.',
          cwe: 'CWE-319',
          benchmark: 'AWS CIS 2.1.2'
        });
      }
    }
  });

  // Cross-statement check: Privilege Escalation Vectors
  ESCALATION_VECTORS.forEach((vector, vIdx) => {
    const hasAll = vector.actions.every(reqAction =>
      allAllowedActions.includes(reqAction) || allAllowedActions.includes('*')
    );
    if (hasAll) {
      privilegeEscalationVectors.push(vector.title);
      findings.unshift({
        id: `iam-escalation-${vIdx}`,
        title: vector.title,
        severity: 'CRITICAL',
        category: 'PRIVILEGE_ESCALATION',
        affectedStatementIndex: 0,
        affectedActionOrResource: vector.actions.join(' + '),
        description: vector.desc,
        attackVector: 'Escalada vertical de privilégios de usuário comum para Root/Admin na nuvem.',
        remediation: 'Remova iam:PassRole irrestrito ou limite a passagem de role para ARNs específicos com restrição de path.',
        cwe: vector.cwe,
        benchmark: 'MITRE ATT&CK T1078.004 / T1548'
      });
    }
  });

  // Calculate score
  const critCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const medCount = findings.filter(f => f.severity === 'MEDIUM').length;

  let penalty = critCount * 35 + highCount * 18 + medCount * 8;
  const riskScore = Math.max(0, 100 - penalty);

  const posture = critCount > 0 || riskScore < 40
    ? 'NON_COMPLIANT'
    : riskScore < 80
    ? 'OVERPRIVILEGED'
    : 'HARDENED';

  return {
    policyName,
    riskScore,
    posture,
    findings,
    wildcardActionsDetected,
    wildcardResourcesDetected,
    privilegeEscalationVectors,
    leastPrivilegePolicySnippet: generateLeastPrivilegePolicy(parsed)
  };
}

function generateLeastPrivilegePolicy(originalParsed: any): string {
  const hardened = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "HardenedLeastPrivilegeScope",
        Effect: "Allow",
        Action: [
          "s3:GetObject",
          "s3:PutObject"
        ],
        Resource: "arn:aws:s3:::meu-bucket-especifico/dados/*",
        Condition: {
          Bool: {
            "aws:SecureTransport": "true"
          }
        }
      },
      {
        Sid: "ExplicitDenyInsecureTransport",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::meu-bucket-especifico",
          "arn:aws:s3:::meu-bucket-especifico/*"
        ],
        Condition: {
          Bool: {
            "aws:SecureTransport": "false"
          }
        }
      }
    ]
  };

  return JSON.stringify(hardened, null, 2);
}
