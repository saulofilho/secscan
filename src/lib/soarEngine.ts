/**
 * SOAR Engine - Security Orchestration, Automation and Response
 * Provides visual playbooks, incident response automation, trigger-condition-action pipelines,
 * integration connectors (Jira, Slack, Firewall, IAM, Vault, Email) and live execution emulator.
 */

export type SoarTriggerType = 
  | 'FINDING_DETECTED' 
  | 'CRITICAL_RISK_THRESHOLD' 
  | 'CTI_THREAT_DETECTED' 
  | 'OPA_POLICY_VIOLATION' 
  | 'SUSPICIOUS_ENDPOINT_FOUND' 
  | 'MANUAL_TRIGGER';

export type SoarActionType = 
  | 'REVOKE_CREDENTIAL' 
  | 'BLOCK_IP_FIREWALL' 
  | 'CREATE_JIRA_TICKET' 
  | 'SEND_SLACK_ALERT' 
  | 'ISOLATE_CONTAINER' 
  | 'ROTATE_KMS_KEY' 
  | 'EXECUTE_PATCH' 
  | 'NOTIFY_SOC_ON_CALL';

export interface SoarPlaybookStep {
  id: string;
  name: string;
  type: 'TRIGGER' | 'CONDITION' | 'ACTION';
  actionType?: SoarActionType;
  triggerType?: SoarTriggerType;
  conditionExpr?: string; // e.g., "finding.severity == 'CRITICAL' && finding.riskScore > 80"
  targetService: 'AWS_IAM' | 'NGFW_FIREWALL' | 'JIRA' | 'SLACK' | 'EDR_AGENT' | 'VAULT_KMS' | 'GIT_PATCH' | 'PAGERDUTY';
  config: Record<string, any>;
  status?: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SKIPPED';
  durationMs?: number;
  outputLog?: string;
}

export interface SoarPlaybook {
  id: string;
  name: string;
  description: string;
  category: 'Incident Response' | 'Credencial Containment' | 'Network Defense' | 'Compliance Automation';
  enabled: boolean;
  trigger: {
    type: SoarTriggerType;
    threshold?: number;
    severity?: string[];
  };
  steps: SoarPlaybookStep[];
  executionCount: number;
  lastRunTimestamp?: string;
  averageExecutionTimeMs: number;
}

export interface SoarExecutionRun {
  id: string;
  playbookId: string;
  playbookName: string;
  startedAt: string;
  completedAt?: string;
  status: 'RUNNING' | 'SUCCESS' | 'FAILED';
  triggeredBy: string;
  stepResults: {
    stepId: string;
    stepName: string;
    status: 'SUCCESS' | 'FAILED' | 'SKIPPED';
    durationMs: number;
    message: string;
    actionResultPayload?: Record<string, any>;
  }[];
  totalDurationMs: number;
}

export const DEFAULT_SOAR_PLAYBOOKS: SoarPlaybook[] = [
  {
    id: 'soar-pb-leaked-cloud-key',
    name: 'Playbook: Contenção de Credencial de Nuvem Vazada',
    description: 'Quando uma credencial AWS/GCP for identificada no código, revoga permissões temporárias no IAM, bloqueia conexões anômalas no NGFW e abre incidente P0 no Jira.',
    category: 'Credencial Containment',
    enabled: true,
    trigger: {
      type: 'FINDING_DETECTED',
      severity: ['CRITICAL', 'HIGH']
    },
    executionCount: 14,
    lastRunTimestamp: new Date(Date.now() - 1000 * 60 * 35).toISOString(),
    averageExecutionTimeMs: 420,
    steps: [
      {
        id: 'step-1',
        name: 'Gatilho: Detecção de Segredo Crítico no SAST',
        type: 'TRIGGER',
        triggerType: 'FINDING_DETECTED',
        targetService: 'AWS_IAM',
        config: { severity: 'CRITICAL', categories: ['Secrets', 'Cloud Key'] }
      },
      {
        id: 'step-2',
        name: 'Condição: Verificar se Credencial é Ativa & de Produção',
        type: 'CONDITION',
        conditionExpr: "finding.category == 'Secrets' && finding.riskScore >= 80",
        targetService: 'AWS_IAM',
        config: { envCheck: 'PRODUCTION' }
      },
      {
        id: 'step-3',
        name: 'Ação: Desativar Access Key no AWS IAM',
        type: 'ACTION',
        actionType: 'REVOKE_CREDENTIAL',
        targetService: 'AWS_IAM',
        config: { action: 'iam:UpdateAccessKey', status: 'Inactive', region: 'us-east-1' }
      },
      {
        id: 'step-4',
        name: 'Ação: Criar Ticket de Segurança P0 no Jira SecOps',
        type: 'ACTION',
        actionType: 'CREATE_JIRA_TICKET',
        targetService: 'JIRA',
        config: { project: 'SEC', issueType: 'Security Incident', priority: 'Highest', assignee: 'SOC-Tier-2' }
      },
      {
        id: 'step-5',
        name: 'Ação: Disparar Alerta Crítico no Slack #sec-incidents',
        type: 'ACTION',
        actionType: 'SEND_SLACK_ALERT',
        targetService: 'SLACK',
        config: { channel: '#sec-incidents', mention: '@oncall-security-lead', urgency: 'URGENT' }
      }
    ]
  },
  {
    id: 'soar-pb-critical-cve-quarantine',
    name: 'Playbook: Quarentena de Endpoint com Vulnerabilidade Crítica',
    description: 'Bloqueia chamadas para endpoints vulneráveis com injeção de SQL ou RCE no Web Application Firewall (WAF) até aplicação do patch.',
    category: 'Network Defense',
    enabled: true,
    trigger: {
      type: 'SUSPICIOUS_ENDPOINT_FOUND',
      threshold: 90
    },
    executionCount: 8,
    lastRunTimestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    averageExecutionTimeMs: 290,
    steps: [
      {
        id: 'step-1',
        name: 'Gatilho: Endpoint de API com Sink Perigoso (SQLi/RCE)',
        type: 'TRIGGER',
        triggerType: 'SUSPICIOUS_ENDPOINT_FOUND',
        targetService: 'NGFW_FIREWALL',
        config: { minRisk: 85 }
      },
      {
        id: 'step-2',
        name: 'Ação: Aplicar Regra Temporária de Drop no WAF / ModSecurity',
        type: 'ACTION',
        actionType: 'BLOCK_IP_FIREWALL',
        targetService: 'NGFW_FIREWALL',
        config: { action: 'DROP', timeoutMinutes: 180, logViolation: true }
      },
      {
        id: 'step-3',
        name: 'Ação: Notificar Engenharia com Patch Sugerido',
        type: 'ACTION',
        actionType: 'SEND_SLACK_ALERT',
        targetService: 'SLACK',
        config: { channel: '#dev-backend-alerts', includePatchDiff: true }
      }
    ]
  },
  {
    id: 'soar-pb-opa-pipeline-break',
    name: 'Playbook: Notificação de Quality Gate & Bloqueio de Pipeline',
    description: 'Quando uma política OPA Rego com nível BLOCKING for violada, cancela o workflow no GitHub Actions e notifica o autor do commit.',
    category: 'Compliance Automation',
    enabled: true,
    trigger: {
      type: 'OPA_POLICY_VIOLATION'
    },
    executionCount: 29,
    lastRunTimestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    averageExecutionTimeMs: 180,
    steps: [
      {
        id: 'step-1',
        name: 'Gatilho: Violação de Guardrail OPA Rego',
        type: 'TRIGGER',
        triggerType: 'OPA_POLICY_VIOLATION',
        targetService: 'JIRA',
        config: { enforcement: 'BLOCKING' }
      },
      {
        id: 'step-2',
        name: 'Ação: Registrar Evidência de Não-Conformidade na Trilha de Auditoria',
        type: 'ACTION',
        actionType: 'CREATE_JIRA_TICKET',
        targetService: 'JIRA',
        config: { type: 'COMPLIANCE_GAP', autoTag: ['SOC2', 'PCI_DSS'] }
      },
      {
        id: 'step-3',
        name: 'Ação: Enviar Resumo Executivo para Gestão de Risco',
        type: 'ACTION',
        actionType: 'NOTIFY_SOC_ON_CALL',
        targetService: 'PAGERDUTY',
        config: { service: 'SecOps-Compliance', escalationLevel: 'Tier-1' }
      }
    ]
  }
];

export function executeSoarPlaybook(playbook: SoarPlaybook, contextData: any = {}): SoarExecutionRun {
  const startTime = performance.now();
  const runId = `run-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
  
  const stepResults = playbook.steps.map(step => {
    const stepDuration = Math.floor(Math.random() * 80) + 30;
    let message = '';
    let actionPayload: Record<string, any> = {};

    switch (step.type) {
      case 'TRIGGER':
        message = `Gatilho validado com sucesso: evento ${step.triggerType} recebido e correlacionado.`;
        actionPayload = { eventReceived: true, payloadSize: '2.4 KB' };
        break;
      case 'CONDITION':
        message = `Condição avaliada como VERDADEIRA (${step.conditionExpr || 'Expressão de guarda satisfeita'}).`;
        actionPayload = { conditionSatisfied: true, matchRatio: '100%' };
        break;
      case 'ACTION':
        switch (step.actionType) {
          case 'REVOKE_CREDENTIAL':
            message = `Credencial revogada no ${step.targetService}. Status: Inactive. Chave marcada para rotação imediata.`;
            actionPayload = { revokedKeyId: 'AKIA***REDACTED', status: 'DEACTIVATED', auditRef: `REV-${Date.now()}` };
            break;
          case 'BLOCK_IP_FIREWALL':
            message = `Regra criada com sucesso no ${step.targetService}: Tráfego suspeito descartado (DROP).`;
            actionPayload = { ruleId: 'FW-RULE-9941', status: 'ENFORCED', ttl: '180m' };
            break;
          case 'CREATE_JIRA_TICKET':
            message = `Ticket SEC-${Math.floor(Math.random() * 9000) + 1000} criado no Jira com severidade Highest e anexo de evidência SAST.`;
            actionPayload = { ticketKey: `SEC-${Math.floor(Math.random() * 9000) + 1000}`, priority: 'P0 - Highest', status: 'OPEN' };
            break;
          case 'SEND_SLACK_ALERT':
            message = `Alerta disparado no Slack ${step.config.channel || '#sec-alerts'} com menção ao time de resposta.`;
            actionPayload = { channel: step.config.channel || '#sec-alerts', dispatched: true, mentionsCount: 1 };
            break;
          case 'NOTIFY_SOC_ON_CALL':
            message = `Incidente escalado para engenheiro On-Call via PagerDuty (Escalação Tier-1).`;
            actionPayload = { incidentId: `PD-${Math.floor(Math.random() * 800000)}`, responseAckWaiting: true };
            break;
          default:
            message = `Ação automatizada ${step.actionType} concluída com código 200 OK.`;
            actionPayload = { success: true };
        }
        break;
    }

    return {
      stepId: step.id,
      stepName: step.name,
      status: 'SUCCESS' as const,
      durationMs: stepDuration,
      message,
      actionResultPayload: actionPayload
    };
  });

  const totalDurationMs = Math.round(performance.now() - startTime) + stepResults.reduce((acc, s) => acc + s.durationMs, 0);

  return {
    id: runId,
    playbookId: playbook.id,
    playbookName: playbook.name,
    startedAt: new Date(Date.now() - totalDurationMs).toISOString(),
    completedAt: new Date().toISOString(),
    status: 'SUCCESS',
    triggeredBy: contextData.triggeredBy || 'SecScan Security Engine',
    stepResults,
    totalDurationMs
  };
}

export function exportPlaybookToYaml(playbook: SoarPlaybook): string {
  return `name: "${playbook.name}"
id: "${playbook.id}"
description: "${playbook.description}"
category: "${playbook.category}"
enabled: ${playbook.enabled}
trigger:
  type: "${playbook.trigger.type}"
  severity: ${JSON.stringify(playbook.trigger.severity || [])}
steps:
${playbook.steps.map((s, idx) => `  - step: ${idx + 1}
    name: "${s.name}"
    type: "${s.type}"
    target: "${s.targetService}"
    ${s.actionType ? `action: "${s.actionType}"` : ''}
    ${s.conditionExpr ? `condition: "${s.conditionExpr}"` : ''}
    config:
      ${JSON.stringify(s.config)}`).join('\n')}
`;
}
