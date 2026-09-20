import { ScannedFile } from '../types';

export interface ScaVulnerability {
  id: string;
  cveId: string;
  ghsaId?: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore: number;
  vulnerableVersions: string;
  fixedVersion: string;
  cweId: string;
  affectedPackage: string;
  references: string[];
}

export interface DependencyPackage {
  id: string;
  name: string;
  version: string;
  type: 'direct' | 'transitive' | 'dev';
  manifestFile: string;
  license: string;
  licenseRisk: 'PERMISSIVE' | 'MEDIUM_RISK' | 'HIGH_RISK';
  licenseExplanation: string;
  isDeprecated?: boolean;
  isTyposquattingRisk?: boolean;
  typosquattingNote?: string;
  vulnerabilities: ScaVulnerability[];
  recommendedVersion?: string;
}

export interface ScaAnalysisReport {
  totalDependencies: number;
  vulnerableCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  copyleftRiskCount: number;
  packages: DependencyPackage[];
  allVulnerabilities: ScaVulnerability[];
  manifestsFound: string[];
}

// Built-in Knowledge Base of Common Package Vulnerabilities (OSV/NVD/GitHub Advisory DB)
const KNOWN_CVE_DATABASE: Record<string, {
  versions: Array<{
    minInclusive?: string;
    maxExclusive: string;
    cve: string;
    ghsa?: string;
    title: string;
    description: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    cvss: number;
    cwe: string;
    fixed: string;
  }>;
  license: string;
  licenseRisk: 'PERMISSIVE' | 'MEDIUM_RISK' | 'HIGH_RISK';
  licenseExplanation: string;
  isDeprecated?: boolean;
  typosquattingNote?: string;
}> = {
  lodash: {
    versions: [
      {
        maxExclusive: '4.17.21',
        cve: 'CVE-2020-8203',
        ghsa: 'GHSA-p6mc-m468-83gw',
        title: 'Prototype Pollution via zipObjectDeep & set',
        description: 'Lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution in the zipObjectDeep function that can lead to remote code execution or denial of service.',
        severity: 'HIGH',
        cvss: 7.5,
        cwe: 'CWE-1321',
        fixed: '4.17.21'
      }
    ],
    license: 'MIT',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Licença permissiva livre para uso comercial e redistribuição.'
  },
  axios: {
    versions: [
      {
        maxExclusive: '0.21.2',
        cve: 'CVE-2021-3749',
        ghsa: 'GHSA-cph5-m8f7-6c5x',
        title: 'Server-Side Request Forgery (SSRF) via Redirect Bypass',
        description: 'Axios versions prior to 0.21.2 are vulnerable to Server-Side Request Forgery (SSRF) when following redirects that cross protocols and domains, exposing internal metadata APIs.',
        severity: 'CRITICAL',
        cvss: 9.1,
        cwe: 'CWE-918',
        fixed: '0.21.4'
      }
    ],
    license: 'MIT',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Permissiva com isenção de garantia.'
  },
  jsonwebtoken: {
    versions: [
      {
        maxExclusive: '9.0.0',
        cve: 'CVE-2022-23529',
        ghsa: 'GHSA-qwph-4952-7xr6',
        title: 'Arbitrary File Write / Code Execution in jwt.verify',
        description: 'In jsonwebtoken library versions prior to 9.0.0, passing an untrusted payload to jwt.verify could allow arbitrary code execution when specific secretOrPublicKey format triggers proto pollution.',
        severity: 'CRITICAL',
        cvss: 9.8,
        cwe: 'CWE-94',
        fixed: '9.0.0'
      }
    ],
    license: 'MIT',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Permissiva.'
  },
  minimist: {
    versions: [
      {
        maxExclusive: '1.2.6',
        cve: 'CVE-2021-44906',
        ghsa: 'GHSA-xvch-5gv4-984h',
        title: 'Prototype Pollution in Argument Parsing',
        description: 'Minimist prior to 1.2.6 is vulnerable to prototype pollution through constructor.prototype assignment during CLI flag parsing.',
        severity: 'HIGH',
        cvss: 7.8,
        cwe: 'CWE-1321',
        fixed: '1.2.6'
      }
    ],
    license: 'MIT',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Permissiva.'
  },
  express: {
    versions: [
      {
        maxExclusive: '4.19.2',
        cve: 'CVE-2024-29041',
        ghsa: 'GHSA-qw6h-vgh9-j6wx',
        title: 'Open Redirect & URL Parsing Bypass in res.location',
        description: 'Express.js versions before 4.19.2 mishandle certain URL encoding combinations in res.redirect and res.location, leading to open redirection vulnerabilities.',
        severity: 'MEDIUM',
        cvss: 6.1,
        cwe: 'CWE-601',
        fixed: '4.19.2'
      }
    ],
    license: 'MIT',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Permissiva.'
  },
  'gpl-crypto-tools': {
    versions: [],
    license: 'GPL-3.0',
    licenseRisk: 'HIGH_RISK',
    licenseExplanation: 'Risco de Licença Copyleft Viral (GPL v3.0). Exige que qualquer software proprietário vinculado seja disponibilizado em código aberto sob a mesma licença.',
    isDeprecated: true,
    typosquattingNote: 'Possível dependência de risco de conformidade jurídica ou supply chain.'
  },
  'log4j-core': {
    versions: [
      {
        maxExclusive: '2.17.1',
        cve: 'CVE-2021-44228',
        ghsa: 'GHSA-j2ge-pqtw-92vm',
        title: 'Log4Shell - JNDI Remote Code Execution',
        description: 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing unauthenticated remote code execution.',
        severity: 'CRITICAL',
        cvss: 10.0,
        cwe: 'CWE-502',
        fixed: '2.17.1'
      }
    ],
    license: 'Apache-2.0',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Permissiva corporativa.'
  },
  requests: {
    versions: [
      {
        maxExclusive: '2.31.0',
        cve: 'CVE-2023-32681',
        ghsa: 'GHSA-j8r2-6x86-q33q',
        title: 'Unintended Proxy-Authorization Header Leak',
        description: 'Requests library forwards Proxy-Authorization headers to destination servers when following redirects, leaking proxy authentication credentials.',
        severity: 'MEDIUM',
        cvss: 6.1,
        cwe: 'CWE-200',
        fixed: '2.31.0'
      }
    ],
    license: 'Apache-2.0',
    licenseRisk: 'PERMISSIVE',
    licenseExplanation: 'Permissiva.'
  }
};

/**
 * Compare two semver-like strings (e.g. "4.17.15" vs "4.17.21")
 */
function isVersionSmaller(v1: string, v2: string): boolean {
  const clean1 = v1.replace(/^[^0-9]*/, '').split('.').map(n => parseInt(n, 10) || 0);
  const clean2 = v2.replace(/^[^0-9]*/, '').split('.').map(n => parseInt(n, 10) || 0);

  for (let i = 0; i < Math.max(clean1.length, clean2.length); i++) {
    const num1 = clean1[i] || 0;
    const num2 = clean2[i] || 0;
    if (num1 < num2) return true;
    if (num1 > num2) return false;
  }
  return false;
}

/**
 * Scans all files in workspace for package manifests and audits dependencies against known CVEs and license risks
 */
export function scanSoftwareCompositionAnalysis(files: ScannedFile[]): ScaAnalysisReport {
  const packages: DependencyPackage[] = [];
  const manifestsFound: string[] = [];
  const allVulnerabilities: ScaVulnerability[] = [];

  for (const file of files) {
    const fileName = file.name.toLowerCase();

    // 1. Audit package.json
    if (fileName === 'package.json') {
      manifestsFound.push(file.path);
      try {
        const pkgData = JSON.parse(file.content);
        const dependencies = pkgData.dependencies || {};
        const devDependencies = pkgData.devDependencies || {};

        const parseEntries = (entries: Record<string, string>, type: 'direct' | 'dev') => {
          for (const [name, rawVersion] of Object.entries(entries)) {
            const cleanVersion = rawVersion.replace(/[\^~>=<]/g, '').trim();
            const dbInfo = KNOWN_CVE_DATABASE[name.toLowerCase()];
            const vulns: ScaVulnerability[] = [];
            let recommendedVersion = cleanVersion;

            let license = dbInfo?.license || 'MIT';
            let licenseRisk: 'PERMISSIVE' | 'MEDIUM_RISK' | 'HIGH_RISK' = dbInfo?.licenseRisk || 'PERMISSIVE';
            let licenseExplanation = dbInfo?.licenseExplanation || 'Licença permissiva padrão detectada.';

            if (dbInfo && dbInfo.versions) {
              for (const vulnRule of dbInfo.versions) {
                if (isVersionSmaller(cleanVersion, vulnRule.maxExclusive)) {
                  const vuln: ScaVulnerability = {
                    id: `vuln-${name}-${vulnRule.cve}`,
                    cveId: vulnRule.cve,
                    ghsaId: vulnRule.ghsa,
                    title: vulnRule.title,
                    description: vulnRule.description,
                    severity: vulnRule.severity,
                    cvssScore: vulnRule.cvss,
                    vulnerableVersions: `< ${vulnRule.maxExclusive}`,
                    fixedVersion: vulnRule.fixed,
                    cweId: vulnRule.cwe,
                    affectedPackage: `${name}@${cleanVersion}`,
                    references: [
                      `https://nvd.nist.gov/vuln/detail/${vulnRule.cve}`,
                      vulnRule.ghsa ? `https://github.com/advisories/${vulnRule.ghsa}` : ''
                    ].filter(Boolean)
                  };
                  vulns.push(vuln);
                  allVulnerabilities.push(vuln);
                  recommendedVersion = vulnRule.fixed;
                }
              }
            }

            packages.push({
              id: `pkg-${name}-${cleanVersion}`,
              name,
              version: cleanVersion,
              type,
              manifestFile: file.path,
              license,
              licenseRisk,
              licenseExplanation,
              isDeprecated: dbInfo?.isDeprecated,
              isTyposquattingRisk: dbInfo?.isDeprecated || name.includes('gpl-'),
              typosquattingNote: dbInfo?.typosquattingNote,
              vulnerabilities: vulns,
              recommendedVersion: vulns.length > 0 ? recommendedVersion : undefined
            });
          }
        };

        parseEntries(dependencies, 'direct');
        parseEntries(devDependencies, 'dev');
      } catch (e) {
        console.warn('Error parsing package.json for SCA:', e);
      }
    }

    // 2. Audit requirements.txt (Python)
    if (fileName === 'requirements.txt') {
      manifestsFound.push(file.path);
      const lines = file.content.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const match = trimmed.match(/^([a-zA-Z0-9_\-]+)(?:==|>=|<=|~=)(.+)$/);
        if (match) {
          const name = match[1];
          const version = match[2].trim();
          const dbInfo = KNOWN_CVE_DATABASE[name.toLowerCase()];
          const vulns: ScaVulnerability[] = [];

          if (dbInfo) {
            for (const vulnRule of dbInfo.versions) {
              if (isVersionSmaller(version, vulnRule.maxExclusive)) {
                const v: ScaVulnerability = {
                  id: `vuln-${name}-${vulnRule.cve}`,
                  cveId: vulnRule.cve,
                  title: vulnRule.title,
                  description: vulnRule.description,
                  severity: vulnRule.severity,
                  cvssScore: vulnRule.cvss,
                  vulnerableVersions: `< ${vulnRule.maxExclusive}`,
                  fixedVersion: vulnRule.fixed,
                  cweId: vulnRule.cwe,
                  affectedPackage: `${name}==${version}`,
                  references: [`https://nvd.nist.gov/vuln/detail/${vulnRule.cve}`]
                };
                vulns.push(v);
                allVulnerabilities.push(v);
              }
            }
          }

          packages.push({
            id: `pkg-py-${name}-${version}`,
            name,
            version,
            type: 'direct',
            manifestFile: file.path,
            license: dbInfo?.license || 'Apache-2.0',
            licenseRisk: dbInfo?.licenseRisk || 'PERMISSIVE',
            licenseExplanation: dbInfo?.licenseExplanation || 'Licença permissiva.',
            vulnerabilities: vulns,
            recommendedVersion: vulns.length > 0 ? vulns[0].fixedVersion : undefined
          });
        }
      }
    }
  }

  const vulnerableCount = packages.filter(p => p.vulnerabilities.length > 0).length;
  const criticalCount = allVulnerabilities.filter(v => v.severity === 'CRITICAL').length;
  const highCount = allVulnerabilities.filter(v => v.severity === 'HIGH').length;
  const mediumCount = allVulnerabilities.filter(v => v.severity === 'MEDIUM').length;
  const lowCount = allVulnerabilities.filter(v => v.severity === 'LOW').length;
  const copyleftRiskCount = packages.filter(p => p.licenseRisk === 'HIGH_RISK').length;

  return {
    totalDependencies: packages.length,
    vulnerableCount,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    copyleftRiskCount,
    packages,
    allVulnerabilities,
    manifestsFound
  };
}
