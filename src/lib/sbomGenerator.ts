import { ScannedFile } from '../types';
import { DependencyPackage, ScaAnalysisReport, scanSoftwareCompositionAnalysis } from './scaScanner';

export type SbomHashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

export interface SbomHash {
  alg: SbomHashAlgorithm;
  /** Hex digest of the published package tarball, as recorded by the lockfile. */
  content: string;
}

export interface SbomComponent {
  name: string;
  version: string;
  type: 'application' | 'library' | 'framework' | 'container';
  purl: string;
  license: string;
  description?: string;
  /** Empty when the workspace has no lockfile for this package. */
  hashes: SbomHash[];
  vulnerabilitiesCount: number;
}

export interface SbomDocument {
  format: 'CycloneDX' | 'SPDX';
  version: string;
  serialNumber: string;
  generatedAt: string;
  appName: string;
  appVersion: string;
  totalComponents: number;
  /** How many components carry a digest read from a lockfile. */
  componentsWithHash: number;
  components: SbomComponent[];
  rawJson: string;
}

const TOOL_NAME = 'SecScan';
const TOOL_VERSION = '0.1.0';
const UNKNOWN_LICENSE = 'NOASSERTION';

const SRI_ALGORITHMS: Record<string, SbomHashAlgorithm> = {
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512'
};

function base64ToHex(value: string): string | null {
  try {
    const binary = atob(value);
    let hex = '';
    for (let i = 0; i < binary.length; i++) {
      hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
  } catch {
    return null;
  }
}

/**
 * Converts a Subresource Integrity string from a lockfile ("sha512-<base64>")
 * into hex digests. It never invents a digest: unknown input yields [].
 */
export function integrityToHashes(integrity?: string): SbomHash[] {
  if (!integrity) return [];
  const hashes: SbomHash[] = [];
  for (const token of integrity.trim().split(/\s+/)) {
    const dash = token.indexOf('-');
    if (dash === -1) continue;
    const alg = SRI_ALGORITHMS[token.slice(0, dash).toLowerCase()];
    const content = base64ToHex(token.slice(dash + 1));
    if (alg && content) hashes.push({ alg, content });
  }
  return hashes;
}

function randomUuid(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface RootApp {
  name: string;
  version: string;
  license?: string;
}

function readRootApp(files: ScannedFile[]): RootApp {
  const manifests = files
    .filter((f) => f.name.toLowerCase() === 'package.json')
    .sort((a, b) => a.path.split('/').length - b.path.split('/').length);
  for (const manifest of manifests) {
    try {
      const parsed = JSON.parse(manifest.content);
      if (parsed && typeof parsed === 'object') {
        return {
          name: typeof parsed.name === 'string' && parsed.name ? parsed.name : 'unnamed-application',
          version: typeof parsed.version === 'string' && parsed.version ? parsed.version : 'unversioned',
          license: typeof parsed.license === 'string' && parsed.license ? parsed.license : undefined
        };
      }
    } catch {
      // Unreadable manifest: try the next one.
    }
  }
  return { name: 'unnamed-application', version: 'unversioned' };
}

function ecosystemOf(pkg: DependencyPackage): 'pypi' | 'npm' {
  return pkg.manifestFile.toLowerCase().endsWith('requirements.txt') ? 'pypi' : 'npm';
}

function purlOf(pkg: DependencyPackage): string {
  const name = pkg.name.startsWith('@') ? `%40${pkg.name.slice(1)}` : pkg.name;
  return `pkg:${ecosystemOf(pkg)}/${name}@${pkg.version}`;
}

function licenseOf(pkg: DependencyPackage): string {
  return pkg.license === 'NOT_IN_CATALOG' ? UNKNOWN_LICENSE : pkg.license;
}

function toComponents(sca: ScaAnalysisReport): SbomComponent[] {
  return sca.packages.map((pkg) => ({
    name: pkg.name,
    version: pkg.version,
    type: 'library',
    purl: purlOf(pkg),
    license: licenseOf(pkg),
    description: `Declarado em ${pkg.manifestFile}`,
    hashes: integrityToHashes(pkg.integrity),
    vulnerabilitiesCount: pkg.vulnerabilities.length
  }));
}

function advisorySource(id: string): { name: string; url: string } {
  return id.startsWith('CVE-')
    ? { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${id}` }
    : { name: 'OSV', url: `https://osv.dev/vulnerability/${id}` };
}

/**
 * Pass the OSV-enriched report as `sca` to carry the advisories into the SBOM.
 * Without it, only the local catalog is consulted.
 */
export function generateCycloneDxSbom(
  files: ScannedFile[],
  sca: ScaAnalysisReport = scanSoftwareCompositionAnalysis(files)
): SbomDocument {
  const serialNumber = `urn:uuid:${randomUuid()}`;
  const now = new Date().toISOString();
  const app = readRootApp(files);
  const components = toComponents(sca);
  const purlByPackage = new Map(sca.packages.map((pkg) => [`${pkg.name}@${pkg.version}`, purlOf(pkg)]));

  const cycloneDxJson = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [{ vendor: TOOL_NAME, name: `${TOOL_NAME} SBOM Generator`, version: TOOL_VERSION }],
      component: {
        type: 'application',
        name: app.name,
        version: app.version,
        ...(app.license ? { licenses: [{ license: { id: app.license } }] } : {}),
        purl: `pkg:npm/${app.name}@${app.version}`
      }
    },
    components: components.map((c) => ({
      type: c.type,
      name: c.name,
      version: c.version,
      purl: c.purl,
      ...(c.license !== UNKNOWN_LICENSE ? { licenses: [{ license: { id: c.license } }] } : {}),
      ...(c.hashes.length > 0 ? { hashes: c.hashes } : {}),
      properties: [{ name: 'secscan:vulnerabilitiesCount', value: String(c.vulnerabilitiesCount) }]
    })),
    vulnerabilities: sca.allVulnerabilities.map((v) => {
      const cwe = parseInt(v.cweId.replace('CWE-', ''), 10);
      const affectedPurl = purlByPackage.get(v.affectedPackage.replace('==', '@'));
      return {
        id: v.cveId,
        source: advisorySource(v.cveId),
        ratings: [
          v.cvssScore > 0
            ? { score: v.cvssScore, severity: v.severity.toLowerCase(), method: 'CVSSv31' }
            : { severity: v.severity.toLowerCase() }
        ],
        ...(Number.isFinite(cwe) ? { cwes: [cwe] } : {}),
        description: v.description,
        ...(/^\d/.test(v.fixedVersion) ? { recommendation: `Upgrade to version ${v.fixedVersion} or higher.` } : {}),
        ...(affectedPurl ? { affects: [{ ref: affectedPurl }] } : {})
      };
    })
  };

  return {
    format: 'CycloneDX',
    version: '1.5',
    serialNumber,
    generatedAt: now,
    appName: app.name,
    appVersion: app.version,
    totalComponents: components.length,
    componentsWithHash: components.filter((c) => c.hashes.length > 0).length,
    components,
    rawJson: JSON.stringify(cycloneDxJson, null, 2)
  };
}

export function generateSpdxSbom(
  files: ScannedFile[],
  sca: ScaAnalysisReport = scanSoftwareCompositionAnalysis(files)
): SbomDocument {
  const now = new Date().toISOString();
  const app = readRootApp(files);
  const components = toComponents(sca);
  const documentId = randomUuid();

  const spdxJson = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${app.name}-SBOM`,
    documentNamespace: `https://spdx.org/spdxdocs/${encodeURIComponent(app.name)}-${documentId}`,
    creationInfo: {
      creators: [`Tool: ${TOOL_NAME}-${TOOL_VERSION}`],
      created: now
    },
    packages: [
      {
        name: app.name,
        SPDXID: 'SPDXRef-Package-Root',
        versionInfo: app.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: app.license || 'NOASSERTION'
      },
      ...components.map((c, idx) => ({
        name: c.name,
        SPDXID: `SPDXRef-Package-${c.name.replace(/[^a-zA-Z0-9]/g, '-')}-${idx}`,
        versionInfo: c.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: c.license,
        ...(c.hashes.length > 0
          ? { checksums: c.hashes.map((h) => ({ algorithm: h.alg.replace('-', ''), checksumValue: h.content })) }
          : {}),
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: c.purl
          }
        ]
      }))
    ],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: 'SPDXRef-Package-Root' },
      ...components.map((c, idx) => ({
        spdxElementId: 'SPDXRef-Package-Root',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-Package-${c.name.replace(/[^a-zA-Z0-9]/g, '-')}-${idx}`
      }))
    ]
  };

  return {
    format: 'SPDX',
    version: '2.3',
    serialNumber: `SPDXRef-DOCUMENT-${documentId}`,
    generatedAt: now,
    appName: app.name,
    appVersion: app.version,
    totalComponents: components.length,
    componentsWithHash: components.filter((c) => c.hashes.length > 0).length,
    components,
    rawJson: JSON.stringify(spdxJson, null, 2)
  };
}
