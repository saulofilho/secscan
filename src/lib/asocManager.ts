import { ScanFinding, ManagedVulnerabilityItem, AsocSlaMetrics, SeverityLevel } from '../types';

// Default corporate SLA policy (Hours)
export const CORPORATE_SLA_POLICY: Record<SeverityLevel, number> = {
  CRITICAL: 48,   // P0: 48 hours (2 days)
  HIGH: 168,      // P1: 168 hours (7 days)
  MEDIUM: 720,    // P2: 720 hours (30 days)
  LOW: 2160,      // P3: 2160 hours (90 days)
  INFO: 4320      // P4: 180 days
};

export const ENGINEERING_TEAMS: Array<'AppSec' | 'Backend' | 'DevOps' | 'Frontend' | 'SecOps'> = [
  'AppSec',
  'Backend',
  'DevOps',
  'Frontend',
  'SecOps'
];

export function buildAsocInventory(findings: ScanFinding[]): {
  items: ManagedVulnerabilityItem[];
  metrics: AsocSlaMetrics;
} {
  const now = new Date();

  if (!findings || findings.length === 0) {
    return {
      items: [],
      metrics: {
        totalVulnerabilities: 0,
        openCount: 0,
        resolvedCount: 0,
        withinSlaCount: 0,
        nearingBreachCount: 0,
        breachedCount: 0,
        exceptionsCount: 0,
        mttrHours: 0,
        slaCompliancePercentage: 100,
        securityDebtScore: 0,
        teamPerformance: ENGINEERING_TEAMS.map(team => ({
          team,
          open: 0,
          breached: 0,
          complianceRate: 100
        }))
      }
    };
  }

  const items: ManagedVulnerabilityItem[] = findings.map((finding, idx) => {
    const policyHours = CORPORATE_SLA_POLICY[finding.severity] || 720;
    
    // Simulate staggered discovery timestamps
    const discoveryOffsetHours = (idx * 14) + (finding.severity === 'CRITICAL' ? 38 : 70);
    const firstDiscoveredDate = new Date(now.getTime() - discoveryOffsetHours * 3600 * 1000);
    const deadlineDate = new Date(firstDiscoveredDate.getTime() + policyHours * 3600 * 1000);

    const remainingHours = Math.round((deadlineDate.getTime() - now.getTime()) / (3600 * 1000));

    let slaStatus: ManagedVulnerabilityItem['slaStatus'] = 'WITHIN_SLA';
    if (remainingHours <= 0) {
      slaStatus = 'BREACHED';
    } else if (remainingHours <= 24) {
      slaStatus = 'NEARING_BREACH';
    }

    // Determine responsible team based on file extension / path
    let assignedTeam: ManagedVulnerabilityItem['assignedTeam'] = 'Backend';
    if (finding.file.includes('Dockerfile') || finding.file.includes('.yaml') || finding.file.includes('.tf')) {
      assignedTeam = 'DevOps';
    } else if (finding.file.includes('component') || finding.file.includes('tsx') || finding.file.includes('html')) {
      assignedTeam = 'Frontend';
    } else if (finding.category === 'PRIVATE_KEY' || finding.category === 'CLOUD_CREDENTIAL' || finding.category === 'API_KEY') {
      assignedTeam = 'AppSec';
    }

    const ownersMap: Record<string, string> = {
      DevOps: 'Carlos Mendes (SRE/DevOps Lead)',
      Backend: 'Lucas Oliveira (Principal Backend Eng)',
      Frontend: 'Juliana Prado (Frontend Tech Lead)',
      AppSec: 'Mariana Souza (AppSec Specialist)',
      SecOps: 'Roberto Silva (SOC Tier 3)'
    };

    return {
      id: `asoc-vuln-${finding.id || idx}`,
      findingId: finding.id,
      title: finding.ruleName || finding.description || 'Falha de Segurança Detectada',
      severity: finding.severity,
      category: finding.category || 'CODE_INSECURITY',
      sourceFile: finding.file,
      line: finding.line,
      firstDiscovered: firstDiscoveredDate.toISOString(),
      slaDeadline: deadlineDate.toISOString(),
      remainingHours,
      slaStatus,
      slaPolicyHours: policyHours,
      assignedOwner: ownersMap[assignedTeam] || 'Equipe de Engenharia',
      assignedTeam,
      remediationCostHours: finding.severity === 'CRITICAL' ? 4 : finding.severity === 'HIGH' ? 8 : 16,
      status: 'OPEN',
      cveOrCwe: finding.ruleId || 'CWE-798'
    };
  });

  // Calculate high-level SLA metrics
  const total = items.length;
  const openCount = items.filter(i => i.status === 'OPEN' || i.status === 'IN_PROGRESS').length;
  const resolvedCount = items.filter(i => i.status === 'RESOLVED').length;
  const breachedCount = items.filter(i => i.slaStatus === 'BREACHED').length;
  const nearingBreachCount = items.filter(i => i.slaStatus === 'NEARING_BREACH').length;
  const withinSlaCount = items.filter(i => i.slaStatus === 'WITHIN_SLA').length;
  const exceptionsCount = items.filter(i => i.status === 'EXCEPTION_APPROVED').length;

  const slaCompliancePercentage = total > 0 ? Math.round(((total - breachedCount) / total) * 100) : 100;
  
  // Security debt score (0 = no debt, 100 = extreme debt)
  const debtPoints = (breachedCount * 30) + (nearingBreachCount * 15) + (openCount * 5);
  const securityDebtScore = Math.min(100, Math.max(0, debtPoints));

  // Team performance breakdown
  const teamPerformance = ENGINEERING_TEAMS.map(team => {
    const teamItems = items.filter(i => i.assignedTeam === team);
    const teamBreached = teamItems.filter(i => i.slaStatus === 'BREACHED').length;
    const complianceRate = teamItems.length > 0
      ? Math.round(((teamItems.length - teamBreached) / teamItems.length) * 100)
      : 100;

    return {
      team,
      open: teamItems.length,
      breached: teamBreached,
      complianceRate
    };
  });

  return {
    items,
    metrics: {
      totalVulnerabilities: total,
      openCount,
      resolvedCount,
      withinSlaCount,
      nearingBreachCount,
      breachedCount,
      exceptionsCount,
      mttrHours: 34.5,
      slaCompliancePercentage,
      securityDebtScore,
      teamPerformance
    }
  };
}
