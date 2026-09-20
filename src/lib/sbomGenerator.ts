import { ScannedFile } from '../types';
import { DependencyPackage, scanSoftwareCompositionAnalysis } from './scaScanner';

export interface SbomComponent {
  name: string;
  version: string;
  type: 'application' | 'library' | 'framework' | 'container';
  purl: string;
  license: string;
  supplier?: string;
  description?: string;
  hashes: {
    sha256: string;
    sha1: string;
  };
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
  components: SbomComponent[];
  rawJson: string;
}

/**
 * Pseudo-random deterministic hash generator for simulated packaging
 */
function generateDeterministicHash(input: string): { sha256: string; sha1: string } {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  const sha256 = (hex + 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855').slice(0, 64);
  const sha1 = (hex + 'da39a3ee5e6b4b0d3255bfef95601890afd80709').slice(0, 40);
  return { sha256, sha1 };
}

export function generateCycloneDxSbom(files: ScannedFile[]): SbomDocument {
  const sca = scanSoftwareCompositionAnalysis(files);
  const serialNumber = `urn:uuid:${Math.random().toString(36).substring(2, 15)}-${Date.now()}`;
  const now = new Date().toISOString();

  // Root application package info
  let appName = 'fintech-enterprise-app';
  let appVersion = '1.4.2';
  const pkgJsonFile = files.find(f => f.name.toLowerCase() === 'package.json');
  if (pkgJsonFile) {
    try {
      const parsed = JSON.parse(pkgJsonFile.content);
      if (parsed.name) appName = parsed.name;
      if (parsed.version) appVersion = parsed.version;
    } catch {}
  }

  const components: SbomComponent[] = sca.packages.map(pkg => {
    const purl = `pkg:npm/${pkg.name}@${pkg.version}`;
    const hashes = generateDeterministicHash(purl);
    return {
      name: pkg.name,
      version: pkg.version,
      type: 'library',
      purl,
      license: pkg.license,
      supplier: 'Open Source Community',
      description: `Dependency package audited in ${pkg.manifestFile}`,
      hashes,
      vulnerabilitiesCount: pkg.vulnerabilities.length
    };
  });

  // CycloneDX v1.5 standard JSON payload
  const cycloneDxJson = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [
        {
          vendor: 'SecScan Enterprise Suite',
          name: 'SecScan SBOM Generator & Signer',
          version: '2.5.0'
        }
      ],
      component: {
        type: 'application',
        name: appName,
        version: appVersion,
        licenses: [{ license: { id: 'Proprietary' } }],
        purl: `pkg:npm/${appName}@${appVersion}`
      }
    },
    components: components.map(c => ({
      type: c.type,
      name: c.name,
      version: c.version,
      purl: c.purl,
      licenses: [{ license: { id: c.license } }],
      hashes: [
        { alg: 'SHA-256', content: c.hashes.sha256 },
        { alg: 'SHA-1', content: c.hashes.sha1 }
      ],
      properties: [
        { name: 'secscan:vulnerabilitiesCount', value: String(c.vulnerabilitiesCount) }
      ]
    })),
    dependencies: components.map(c => ({
      ref: c.purl,
      dependsOn: []
    })),
    vulnerabilities: sca.allVulnerabilities.map(v => ({
      id: v.cveId,
      source: { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${v.cveId}` },
      ratings: [{ score: v.cvssScore, severity: v.severity.toLowerCase(), method: 'CVSSv31' }],
      cwes: [parseInt(v.cweId.replace('CWE-', ''), 10) || 79],
      description: v.description,
      recommendation: `Upgrade to version ${v.fixedVersion} or higher.`
    }))
  };

  return {
    format: 'CycloneDX',
    version: '1.5',
    serialNumber,
    generatedAt: now,
    appName,
    appVersion,
    totalComponents: components.length,
    components,
    rawJson: JSON.stringify(cycloneDxJson, null, 2)
  };
}

export function generateSpdxSbom(files: ScannedFile[]): SbomDocument {
  const sca = scanSoftwareCompositionAnalysis(files);
  const now = new Date().toISOString();

  let appName = 'fintech-enterprise-app';
  let appVersion = '1.4.2';
  const pkgJsonFile = files.find(f => f.name.toLowerCase() === 'package.json');
  if (pkgJsonFile) {
    try {
      const parsed = JSON.parse(pkgJsonFile.content);
      if (parsed.name) appName = parsed.name;
      if (parsed.version) appVersion = parsed.version;
    } catch {}
  }

  const components: SbomComponent[] = sca.packages.map(pkg => {
    const purl = `pkg:npm/${pkg.name}@${pkg.version}`;
    const hashes = generateDeterministicHash(purl);
    return {
      name: pkg.name,
      version: pkg.version,
      type: 'library',
      purl,
      license: pkg.license,
      hashes,
      vulnerabilitiesCount: pkg.vulnerabilities.length
    };
  });

  const spdxJson = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${appName}-SBOM`,
    documentNamespace: `https://secscan.enterprise/spdx/${appName}/${Date.now()}`,
    creationInfo: {
      creators: ['Tool: SecScan-AppSec-Suite-2.5', 'Organization: Enterprise AppSec Team'],
      created: now
    },
    packages: [
      {
        name: appName,
        SPDXID: 'SPDXRef-Package-Root',
        versionInfo: appVersion,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: true,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'Proprietary'
      },
      ...components.map((c, idx) => ({
        name: c.name,
        SPDXID: `SPDXRef-Package-${c.name.replace(/[^a-zA-Z0-9]/g, '-')}-${idx}`,
        versionInfo: c.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: c.license,
        checksums: [
          { algorithm: 'SHA256', checksumValue: c.hashes.sha256 },
          { algorithm: 'SHA1', checksumValue: c.hashes.sha1 }
        ],
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: c.purl
          }
        ]
      }))
    ]
  };

  return {
    format: 'SPDX',
    version: '2.3',
    serialNumber: `SPDXRef-DOCUMENT-${Date.now()}`,
    generatedAt: now,
    appName,
    appVersion,
    totalComponents: components.length,
    components,
    rawJson: JSON.stringify(spdxJson, null, 2)
  };
}
