import { ScanSchedule, ScheduleInterval, CiCdProvider } from '../types';

export interface SchedulePreset {
  id: ScheduleInterval;
  label: string;
  cron: string;
  description: string;
}

export const SCHEDULE_PRESETS: SchedulePreset[] = [
  {
    id: 'HOURLY',
    label: 'A Cada Hora',
    cron: '0 * * * *',
    description: 'Executa no minuto zero de cada hora (repositórios de alta rotatividade)'
  },
  {
    id: 'EVERY_6_HOURS',
    label: 'A Cada 6 Horas',
    cron: '0 */6 * * *',
    description: 'Executa 4 vezes ao dia (00:00, 06:00, 12:00, 18:00 UTC)'
  },
  {
    id: 'DAILY_MIDNIGHT',
    label: 'Diário (Meia-Noite UTC)',
    cron: '0 0 * * *',
    description: 'Auditoria noturna diária antes do início do expediente'
  },
  {
    id: 'WEEKDAY_MORNING',
    label: 'Dias Úteis (08:00 UTC)',
    cron: '0 8 * * 1-5',
    description: 'Executa de segunda a sexta-feira às 08:00 UTC'
  },
  {
    id: 'WEEKLY_SUNDAY',
    label: 'Semanal (Domingo 00:00 UTC)',
    cron: '0 0 * * 0',
    description: 'Varredura semanal consolidada para compliance contínuo'
  },
  {
    id: 'CUSTOM_CRON',
    label: 'Expressão Cron Customizada',
    cron: '0 2 * * *',
    description: 'Defina uma sintaxe cron POSIX de 5 campos (min hora dia mês dow)'
  }
];

export const INITIAL_SCHEDULES: ScanSchedule[] = [
  {
    id: 'sched-1',
    name: 'Main Production Vault Scan',
    repository: 'organization/core-backend-api',
    branch: 'main',
    cronExpression: '0 0 * * *',
    intervalPreset: 'DAILY_MIDNIGHT',
    provider: 'github-actions',
    enabled: true,
    failOnSeverity: 'CRITICAL',
    notifyChannels: ['webhook', 'pr_comment'],
    lastRun: {
      timestamp: 'Hoje às 00:00 UTC',
      status: 'WARNING',
      findingsCount: 3,
      securityImpactScore: 78,
      durationMs: 412
    },
    nextRun: 'Amanhã às 00:00 UTC',
    createdAt: '2026-08-25T14:00:00Z'
  },
  {
    id: 'sched-2',
    name: 'Auth & Secrets Hourly Audit',
    repository: 'organization/identity-auth-service',
    branch: 'production',
    cronExpression: '0 * * * *',
    intervalPreset: 'HOURLY',
    provider: 'github-actions',
    enabled: true,
    failOnSeverity: 'HIGH',
    notifyChannels: ['webhook'],
    lastRun: {
      timestamp: 'Há 45 minutos',
      status: 'SUCCESS',
      findingsCount: 0,
      securityImpactScore: 0,
      durationMs: 230
    },
    nextRun: 'Em 15 minutos',
    createdAt: '2026-08-28T09:30:00Z'
  },
  {
    id: 'sched-3',
    name: 'Frontend Microapps Security Audit',
    repository: 'organization/cloud-console-web',
    branch: 'release/v4.2',
    cronExpression: '0 8 * * 1-5',
    intervalPreset: 'WEEKDAY_MORNING',
    provider: 'gitlab-ci',
    enabled: false,
    failOnSeverity: 'CRITICAL',
    notifyChannels: ['email'],
    lastRun: {
      timestamp: 'Sexta-feira às 08:00 UTC',
      status: 'SUCCESS',
      findingsCount: 1,
      securityImpactScore: 12,
      durationMs: 380
    },
    nextRun: 'Pausado',
    createdAt: '2026-09-01T11:00:00Z'
  }
];

/**
 * Validates a 5-part cron expression (minute hour day-of-month month day-of-week)
 */
export function validateCron(cron: string): { valid: boolean; message?: string } {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) {
    return { valid: false, message: 'A expressão cron precisa conter exatamente 5 campos (min hora dia mês dia-da-semana).' };
  }
  return { valid: true };
}

/**
 * Translates cron expression to readable human summary
 */
export function describeCron(cron: string): string {
  const trimmed = cron.trim();
  const preset = SCHEDULE_PRESETS.find(p => p.cron === trimmed);
  if (preset && preset.id !== 'CUSTOM_CRON') {
    return `${preset.label} (${preset.cron})`;
  }
  if (trimmed === '0 * * * *') return 'A cada hora no minuto zero';
  if (trimmed === '0 0 * * *') return 'Diariamente às 00:00 UTC';
  if (trimmed === '0 */6 * * *') return 'A cada 6 horas';
  if (trimmed === '0 8 * * 1-5') return 'Dias úteis (Seg-Sex) às 08:00 UTC';
  if (trimmed === '0 0 * * 0') return 'Todos os domingos às 00:00 UTC';
  return `Cron customizado: "${trimmed}"`;
}

/**
 * Generates CI/CD configuration snippet for scheduled scans
 */
export function generateScheduledPipelineConfig(schedule: ScanSchedule): string {
  if (schedule.provider === 'gitlab-ci') {
    return `# .gitlab-ci.yml (Scheduled Pipeline)
stages:
  - security-audit

secscan_scheduled_audit:
  stage: security-audit
  image: node:22-alpine
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - npm ci || npm install
    - npx secscan . --repo "${schedule.repository}" --branch "${schedule.branch}" --fail-on ${schedule.failOnSeverity.toLowerCase()} --format sarif --output secscan-report.sarif
  artifacts:
    reports:
      sast: secscan-report.sarif
    expire_in: 30 days
`;
  }

  // GitHub Actions schedule syntax using on.schedule.cron
  return `# .github/workflows/secscan-schedule.yml
name: SecScan Scheduled Repository Audit

on:
  schedule:
    # Agendamento configurado: ${describeCron(schedule.cronExpression)}
    - cron: '${schedule.cronExpression}'
  workflow_dispatch: # Permite disparo manual via GitHub UI

permissions:
  contents: read
  security-events: write

jobs:
  scheduled-scan:
    name: Audit ${schedule.repository} (${schedule.branch})
    runs-on: ubuntu-latest
    steps:
      - name: 📥 Checkout Repository
        uses: actions/checkout@v4
        with:
          ref: '${schedule.branch}'

      - name: ⚙️ Setup Node.js 22 LTS
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: 📦 Install SecScan
        run: npm ci || npm install

      - name: 🔍 Execute Scheduled Security Scan
        run: |
          npx secscan . \\
            --branch "${schedule.branch}" \\
            --fail-on ${schedule.failOnSeverity.toLowerCase()} \\
            --format sarif \\
            --output secscan-report.sarif

      - name: 🛡️ Publish SARIF Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secscan-report.sarif
`;
}
