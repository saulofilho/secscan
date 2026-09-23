/**
 * Dark Web & Compromised Credential Engine
 * Detects corporate emails in repositories and correlates against Dark Web breach dumps,
 * stealer malware logs (RedLine, Lumma, Racoon), pastebins, and credential exposures.
 */

export interface CompromisedAccount {
  email: string;
  sourceBreach: string;
  breachDate: string;
  dataExposed: string[];
  stealerType?: 'RedLine Stealer' | 'LummaC2' | 'Racoon v2' | 'Underground Forum Dump';
  hashType: 'SHA-1' | 'BCRYPT' | 'MD5' | 'PLAINTEXT';
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  remediationStatus: 'REVOCATION_REQUIRED' | 'MFA_ENFORCED' | 'RESOLVED';
  foundInRepoFile?: string;
}

export const SAMPLE_DARK_WEB_BREACHES: CompromisedAccount[] = [
  {
    email: 'devops-lead@enterprise.corp',
    sourceBreach: 'LummaC2 Infostealer Telegram Botnet Dump',
    breachDate: '2026-02-14',
    dataExposed: ['Email', 'Corporate SSO Password', 'Browser Cookies', 'AWS Session Token'],
    stealerType: 'LummaC2',
    hashType: 'PLAINTEXT',
    riskLevel: 'CRITICAL',
    remediationStatus: 'REVOCATION_REQUIRED',
    foundInRepoFile: 'src/services/deployService.ts'
  },
  {
    email: 'secops-admin@enterprise.corp',
    sourceBreach: 'BreachForums Database Dump #419',
    breachDate: '2025-11-20',
    dataExposed: ['Email', 'Hashed Password', 'Job Title', 'Phone Number'],
    stealerType: 'Underground Forum Dump',
    hashType: 'BCRYPT',
    riskLevel: 'HIGH',
    remediationStatus: 'MFA_ENFORCED',
    foundInRepoFile: 'docker-compose.yml'
  },
  {
    email: 'backend-eng@enterprise.corp',
    sourceBreach: 'RedLine Stealer Infected Endpoint Log',
    breachDate: '2026-01-08',
    dataExposed: ['Email', 'Git Credentials', 'SSH Private Key Passphrase'],
    stealerType: 'RedLine Stealer',
    hashType: 'PLAINTEXT',
    riskLevel: 'CRITICAL',
    remediationStatus: 'REVOCATION_REQUIRED',
    foundInRepoFile: 'src/config/database.ts'
  }
];

export function extractEmailsFromFiles(files: { name: string; content: string }[]): string[] {
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const discovered = new Set<string>();

  files.forEach(f => {
    const matches = f.content.match(emailRegex);
    if (matches) {
      matches.forEach(email => discovered.add(email.toLowerCase()));
    }
  });

  return Array.from(discovered);
}
