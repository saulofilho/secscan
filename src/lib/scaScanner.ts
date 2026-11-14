import { ScannedFile } from '../types';
import { calculateCvssScore, CvssMetrics } from './threatModeler';

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
  licenseRisk: 'PERMISSIVE' | 'MEDIUM_RISK' | 'HIGH_RISK' | 'NOT_IN_CATALOG';
  licenseExplanation: string;
  isDeprecated?: boolean;
  isTyposquattingRisk?: boolean;
  typosquattingNote?: string;
  vulnerabilities: ScaVulnerability[];
  recommendedVersion?: string;
  /** SRI do lockfile (ex.: sha512-...). Ausente quando não há lockfile. */
  integrity?: string;
  /** true quando a versão veio do lockfile e não do range do manifesto. */
  versionFromLockfile?: boolean;
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
  catalogMode: 'CURATED_LOCAL' | 'OSV';
  catalogSize: number;
  osvStatus: 'NOT_QUERIED' | 'OK' | 'UNREACHABLE';
}

// Curated local sample. Packages absent from this map are reported as NOT_IN_CATALOG.
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


interface LockEntry {
  name: string;
  version: string;
  integrity?: string;
  dev: boolean;
  topLevel: boolean;
}

function dirOf(filePath: string): string {
  const idx = filePath.lastIndexOf('/');
  return idx === -1 ? '' : filePath.slice(0, idx);
}

/**
 * Reads package-lock.json (v1, v2 and v3). Returns every installed package with
 * the exact version and the integrity hash npm recorded.
 */
export function parsePackageLock(content: string): LockEntry[] {
  let data: any;
  try {
    data = JSON.parse(content);
  } catch {
    return [];
  }
  const entries: LockEntry[] = [];
  if (data && typeof data.packages === 'object' && data.packages) {
    for (const [key, raw] of Object.entries<any>(data.packages)) {
      if (!key || !raw || typeof raw.version !== 'string' || raw.link) continue;
      const marker = key.lastIndexOf('node_modules/');
      if (marker === -1) continue;
      const name = key.slice(marker + 'node_modules/'.length);
      entries.push({
        name,
        version: raw.version,
        integrity: typeof raw.integrity === 'string' ? raw.integrity : undefined,
        dev: raw.dev === true,
        topLevel: key === `node_modules/${name}`
      });
    }
    return entries;
  }
  const walk = (deps: any, topLevel: boolean) => {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, raw] of Object.entries<any>(deps)) {
      if (!raw || typeof raw.version !== 'string') continue;
      entries.push({
        name,
        version: raw.version,
        integrity: typeof raw.integrity === 'string' ? raw.integrity : undefined,
        dev: raw.dev === true,
        topLevel
      });
      walk(raw.dependencies, false);
    }
  };
  walk(data?.dependencies, true);
  return entries;
}

/**
 * Scans all files in workspace for package manifests and audits dependencies against known CVEs and license risks
 */
export function scanSoftwareCompositionAnalysis(files: ScannedFile[]): ScaAnalysisReport {
  const packages: DependencyPackage[] = [];
  const manifestsFound: string[] = [];
  const allVulnerabilities: ScaVulnerability[] = [];

  const locksByDir = new Map<string, { path: string; entries: LockEntry[] }>();
  for (const file of files) {
    if (file.name.toLowerCase() === 'package-lock.json') {
      const entries = parsePackageLock(file.content);
      if (entries.length > 0) locksByDir.set(dirOf(file.path), { path: file.path, entries });
    }
  }

  for (const file of files) {
    const fileName = file.name.toLowerCase();

    // 1. Audit package.json
    if (fileName === 'package.json') {
      manifestsFound.push(file.path);
      try {
        const pkgData = JSON.parse(file.content);
        const dependencies = pkgData.dependencies || {};
        const devDependencies = pkgData.devDependencies || {};

        const lock = locksByDir.get(dirOf(file.path));
        const seen = new Set<string>();
        const parseEntries = (entries: Record<string, string>, type: 'direct' | 'dev' | 'transitive', lockEntry?: LockEntry) => {
          for (const [name, rawVersion] of Object.entries(entries)) {
            const locked = lockEntry || lock?.entries.find((entry) => entry.topLevel && entry.name === name);
            const cleanVersion = locked ? locked.version : String(rawVersion).replace(/[\^~>=<]/g, '').trim();
            if (seen.has(`${name}@${cleanVersion}`)) continue;
            seen.add(`${name}@${cleanVersion}`);
            const dbInfo = KNOWN_CVE_DATABASE[name.toLowerCase()];
            const vulns: ScaVulnerability[] = [];
            let recommendedVersion = cleanVersion;

            let license = dbInfo?.license || 'NOT_IN_CATALOG';
            let licenseRisk: 'PERMISSIVE' | 'MEDIUM_RISK' | 'HIGH_RISK' | 'NOT_IN_CATALOG' = dbInfo?.licenseRisk || 'NOT_IN_CATALOG';
            let licenseExplanation = dbInfo?.licenseExplanation || 'Pacote ausente do catálogo local. Licença e CVEs não foram consultados.';

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
              manifestFile: lockEntry && lock ? lock.path : file.path,
              integrity: locked?.integrity,
              versionFromLockfile: Boolean(locked),
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
        if (lock) {
          for (const entry of lock.entries) {
            parseEntries({ [entry.name]: entry.version }, entry.dev ? 'dev' : 'transitive', entry);
          }
        }
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
            license: dbInfo?.license || 'NOT_IN_CATALOG',
            licenseRisk: dbInfo?.licenseRisk || 'NOT_IN_CATALOG',
            licenseExplanation: dbInfo?.licenseExplanation || 'Pacote ausente do catálogo local. Licença e CVEs não foram consultados.',
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
    manifestsFound,
    catalogMode: 'CURATED_LOCAL',
    catalogSize: Object.keys(KNOWN_CVE_DATABASE).length,
    osvStatus: 'NOT_QUERIED'
  };
}

type OsvFetch = (input: string, init?: RequestInit) => Promise<Response>;

function ecosystemForManifest(manifestFile: string): 'npm' | 'PyPI' {
  return manifestFile.toLowerCase().endsWith('requirements.txt') ? 'PyPI' : 'npm';
}

/** CVSS v3.x base score from the vector string. Returns null for other versions. */
export function cvss3BaseScoreFromVector(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const parts = new Map<string, string>();
  for (const chunk of vector.split('/').slice(1)) {
    const [key, value] = chunk.split(':');
    if (key && value) parts.set(key, value);
  }
  const pick = <T extends string>(key: string, table: Record<string, T>): T | null => table[parts.get(key) || ''] || null;
  const level = { N: 'NONE', L: 'LOW', H: 'HIGH' } as const;
  const metrics = {
    attackVector: pick('AV', { N: 'NETWORK', A: 'ADJACENT', L: 'LOCAL', P: 'PHYSICAL' } as const),
    attackComplexity: pick('AC', { L: 'LOW', H: 'HIGH' } as const),
    privilegesRequired: pick('PR', level),
    userInteraction: pick('UI', { N: 'NONE', R: 'REQUIRED' } as const),
    scope: pick('S', { U: 'UNCHANGED', C: 'CHANGED' } as const),
    confidentiality: pick('C', level),
    integrity: pick('I', level),
    availability: pick('A', level)
  };
  if (Object.values(metrics).some((value) => value === null)) return null;
  return calculateCvssScore(metrics as CvssMetrics).baseScore;
}

function severityFromScore(score: number): ScaVulnerability['severity'] {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

function osvSeverity(vuln: Record<string, unknown>): { severity: ScaVulnerability['severity']; cvssScore: number } {
  const scores = Array.isArray(vuln.severity) ? vuln.severity : [];
  let cvssScore = 0;
  for (const entry of scores) {
    const raw = String((entry as { score?: string }).score || '');
    const numeric = Number(raw);
    const score = Number.isFinite(numeric) && numeric > 0 ? numeric : cvss3BaseScoreFromVector(raw);
    if (score && score > 0) {
      cvssScore = score;
      break;
    }
  }

  const databaseSpecific = vuln.database_specific as { severity?: string } | undefined;
  const label = String(databaseSpecific?.severity || '').toUpperCase();
  if (label === 'CRITICAL') return { severity: 'CRITICAL', cvssScore };
  if (label === 'HIGH') return { severity: 'HIGH', cvssScore };
  if (label === 'MODERATE' || label === 'MEDIUM') return { severity: 'MEDIUM', cvssScore };
  if (label === 'LOW') return { severity: 'LOW', cvssScore };
  if (cvssScore > 0) return { severity: severityFromScore(cvssScore), cvssScore };
  // The advisory carries no rating. cvssScore 0 marks it as unrated.
  return { severity: 'MEDIUM', cvssScore: 0 };
}

function osvFixedVersion(vuln: Record<string, unknown>, packageName: string): string {
  const affected = Array.isArray(vuln.affected) ? vuln.affected : [];
  const sameName = affected.filter((item) => (item as { package?: { name?: string } }).package?.name === packageName);
  for (const item of sameName.length > 0 ? sameName : affected) {
    const ranges = Array.isArray((item as { ranges?: unknown }).ranges) ? (item as { ranges: unknown[] }).ranges : [];
    for (const range of ranges) {
      const events = Array.isArray((range as { events?: unknown }).events) ? (range as { events: unknown[] }).events : [];
      const fixed = events.find((event) => typeof (event as { fixed?: string }).fixed === 'string') as { fixed?: string } | undefined;
      if (fixed?.fixed) return fixed.fixed;
    }
  }
  return 'ver advisory';
}

function osvToVulnerability(vuln: Record<string, unknown>, pkg: DependencyPackage): ScaVulnerability | null {
  const id = String(vuln.id || '');
  if (!id) return null;
  const aliases = Array.isArray(vuln.aliases) ? vuln.aliases.map(String) : [];
  const ids = [id, ...aliases];
  const cveId = ids.find((value) => value.startsWith('CVE-')) || id;
  const ghsaId = ids.find((value) => value.startsWith('GHSA-'));
  const already = pkg.vulnerabilities.some((known) => known.cveId === cveId || (ghsaId && known.ghsaId === ghsaId));
  if (already) return null;

  const ranked = osvSeverity(vuln);
  const references = (Array.isArray(vuln.references) ? vuln.references : [])
    .map((item) => String((item as { url?: string }).url || ''))
    .filter(Boolean)
    .slice(0, 3);
  references.push(`https://osv.dev/vulnerability/${id}`);

  return {
    id: `osv-${pkg.name}-${id}`,
    cveId,
    ghsaId,
    title: String(vuln.summary || id),
    description: String(vuln.details || vuln.summary || 'Advisory publicado no OSV.'),
    severity: ranked.severity,
    cvssScore: ranked.cvssScore,
    vulnerableVersions: pkg.version,
    fixedVersion: osvFixedVersion(vuln, pkg.name),
    cweId: String((vuln.database_specific as { cwe_ids?: string[] } | undefined)?.cwe_ids?.[0] || ''),
    affectedPackage: `${pkg.name}@${pkg.version}`,
    references
  };
}

function recountSca(packages: DependencyPackage[], base: ScaAnalysisReport, osvStatus: ScaAnalysisReport['osvStatus']): ScaAnalysisReport {
  const allVulnerabilities = packages.flatMap((pkg) => pkg.vulnerabilities);
  return {
    ...base,
    packages,
    allVulnerabilities,
    vulnerableCount: packages.filter((pkg) => pkg.vulnerabilities.length > 0).length,
    criticalCount: allVulnerabilities.filter((vuln) => vuln.severity === 'CRITICAL').length,
    highCount: allVulnerabilities.filter((vuln) => vuln.severity === 'HIGH').length,
    mediumCount: allVulnerabilities.filter((vuln) => vuln.severity === 'MEDIUM').length,
    lowCount: allVulnerabilities.filter((vuln) => vuln.severity === 'LOW').length,
    catalogMode: osvStatus === 'OK' ? 'OSV' : 'CURATED_LOCAL',
    osvStatus
  };
}

const OSV_API = 'https://api.osv.dev/v1';
const OSV_BATCH_SIZE = 1000;
const OSV_DETAIL_CONCURRENCY = 8;
const osvDetailCache = new Map<string, Record<string, unknown>>();

type OsvVuln = Record<string, unknown>;

function isBareOsvRecord(vuln: OsvVuln): boolean {
  return vuln.summary === undefined && vuln.details === undefined && vuln.affected === undefined;
}

/**
 * /v1/querybatch answers with id and modified only. The summary, severity and
 * fixed version come from /v1/vulns/{id}, one request per advisory.
 */
async function hydrateOsvRecords(ids: string[], fetchImpl: OsvFetch, signal: AbortSignal): Promise<void> {
  const pending = ids.filter((id) => !osvDetailCache.has(id));
  let cursor = 0;
  const worker = async () => {
    while (cursor < pending.length) {
      const id = pending[cursor];
      cursor += 1;
      try {
        const response = await fetchImpl(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { signal });
        if (!response.ok) continue;
        const detail = await response.json() as Record<string, unknown>;
        if (detail && typeof detail === 'object' && detail.id) osvDetailCache.set(id, detail);
      } catch {
        // A advisory without detail stays listed by id.
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(OSV_DETAIL_CONCURRENCY, pending.length) }, worker));
}

/**
 * Asks api.osv.dev for advisories. Package names and versions leave the machine.
 * A failed request leaves the local catalog unchanged.
 */
export async function enrichScaReportWithOsv(
  report: ScaAnalysisReport,
  fetchImpl: OsvFetch = fetch
): Promise<ScaAnalysisReport> {
  if (report.packages.length === 0) return report;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const remoteByIndex: OsvVuln[][] = [];
    for (let start = 0; start < report.packages.length; start += OSV_BATCH_SIZE) {
      const chunk = report.packages.slice(start, start + OSV_BATCH_SIZE);
      const response = await fetchImpl(`${OSV_API}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          queries: chunk.map((pkg) => ({
            package: { name: pkg.name, ecosystem: ecosystemForManifest(pkg.manifestFile) },
            version: pkg.version
          }))
        }),
        signal: controller.signal
      });
      const contentType = response.headers.get('content-type') || '';
      if (!response.ok || !contentType.includes('application/json')) {
        return { ...report, osvStatus: 'UNREACHABLE' };
      }
      const body = await response.json() as { results?: Array<{ vulns?: OsvVuln[] }> };
      const results = Array.isArray(body.results) ? body.results : [];
      chunk.forEach((_, index) => {
        const vulns = results[index]?.vulns;
        remoteByIndex[start + index] = Array.isArray(vulns) ? vulns : [];
      });
    }

    const bareIds = new Set<string>();
    for (const vulns of remoteByIndex) {
      for (const vuln of vulns) {
        if (vuln.id && isBareOsvRecord(vuln)) bareIds.add(String(vuln.id));
      }
    }
    if (bareIds.size > 0) await hydrateOsvRecords([...bareIds], fetchImpl, controller.signal);

    const packages = report.packages.map((pkg, index) => {
      const remote = remoteByIndex[index] || [];
      const added = remote
        .map((vuln) => (isBareOsvRecord(vuln) && osvDetailCache.get(String(vuln.id))) || vuln)
        .map((vuln) => osvToVulnerability(vuln, pkg))
        .filter((vuln): vuln is ScaVulnerability => vuln !== null);
      const licenseExplanation = pkg.license === 'NOT_IN_CATALOG'
        ? (added.length > 0
          ? 'Licença ausente do catálogo local. Vulnerabilidades desta versão vieram do OSV.'
          : 'Licença ausente do catálogo local. O OSV não publicou vulnerabilidade para esta versão.')
        : pkg.licenseExplanation;
      const vulnerabilities = [...pkg.vulnerabilities, ...added];
      const fixes = vulnerabilities.map((vuln) => vuln.fixedVersion).filter((fixed) => /^\d/.test(fixed));
      const recommendedVersion = fixes.reduce<string | undefined>(
        (best, fixed) => (!best || isVersionSmaller(best, fixed) ? fixed : best),
        undefined
      );
      return {
        ...pkg,
        licenseExplanation,
        vulnerabilities,
        recommendedVersion: recommendedVersion || pkg.recommendedVersion
      };
    });
    return recountSca(packages, report, 'OK');
  } catch {
    return { ...report, osvStatus: 'UNREACHABLE' };
  } finally {
    clearTimeout(timer);
  }
}
