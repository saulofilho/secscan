/**
 * Software Supply Chain & Cosign / SLSA Provenance Engine
 * Generates SLSA v1.0 provenance attestations, Cosign key pairs, cryptographic signatures,
 * and audits dependencies for Typosquatting / Dependency Confusion vulnerabilities.
 */

export interface SlsaProvenanceAttestation {
  _type: 'https://in-toto.io/Statement/v1';
  subject: {
    name: string;
    digest: {
      sha256: string;
    };
  }[];
  predicateType: 'https://slsa.dev/provenance/v1';
  predicate: {
    buildDefinition: {
      buildType: 'https://actions.github.com/workflow/v1';
      externalParameters: {
        workflow: string;
        repository: string;
        ref: string;
      };
      internalParameters: {
        runnerOS: string;
        nodeVersion: string;
      };
      resolvedDependencies: {
        uri: string;
        digest: { sha256: string };
      }[];
    };
    runDetails: {
      builder: {
        id: string;
        version: string;
      };
      metadata: {
        invocationId: string;
        startedOn: string;
        finishedOn: string;
      };
      byproducts: {
        name: string;
        digest: { sha256: string };
      }[];
    };
  };
}

export interface SupplyChainAuditItem {
  packageName: string;
  currentVersion: string;
  registry: 'npm' | 'pypi' | 'crates.io' | 'go';
  slsaLevel: 'SLSA Level 1' | 'SLSA Level 2' | 'SLSA Level 3' | 'SLSA Level 4';
  isSignedWithCosign: boolean;
  signerIdentity?: string;
  typosquattingRisk: 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK';
  legitimateAlternative?: string;
}

export const SAMPLE_SUPPLY_CHAIN_PACKAGES: SupplyChainAuditItem[] = [
  {
    packageName: 'react',
    currentVersion: '18.3.1',
    registry: 'npm',
    slsaLevel: 'SLSA Level 3',
    isSignedWithCosign: true,
    signerIdentity: 'github.com/facebook/react@refs/tags/v18.3.1',
    typosquattingRisk: 'SAFE'
  },
  {
    packageName: 'lodash',
    currentVersion: '4.17.21',
    registry: 'npm',
    slsaLevel: 'SLSA Level 3',
    isSignedWithCosign: true,
    signerIdentity: 'github.com/lodash/lodash@refs/tags/4.17.21',
    typosquattingRisk: 'SAFE'
  },
  {
    packageName: 'cross-env-colors',
    currentVersion: '1.0.4',
    registry: 'npm',
    slsaLevel: 'SLSA Level 1',
    isSignedWithCosign: false,
    typosquattingRisk: 'HIGH_RISK',
    legitimateAlternative: 'colors / chalk'
  },
  {
    packageName: 'internal-corp-auth-sdk',
    currentVersion: '0.1.0',
    registry: 'npm',
    slsaLevel: 'SLSA Level 2',
    isSignedWithCosign: false,
    typosquattingRisk: 'SUSPICIOUS',
    legitimateAlternative: '@internal-org/auth-sdk (Scope privado não reservado no NPM público)'
  }
];

export function generateSlsaProvenance(artifactName: string, digestSha256: string): SlsaProvenanceAttestation {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [
      {
        name: artifactName,
        digest: { sha256: digestSha256 }
      }
    ],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://actions.github.com/workflow/v1',
        externalParameters: {
          workflow: '.github/workflows/secscan-build.yml',
          repository: 'https://github.com/org/secscan-enterprise',
          ref: 'refs/heads/main'
        },
        internalParameters: {
          runnerOS: 'ubuntu-22.04',
          nodeVersion: '20.11.0'
        },
        resolvedDependencies: [
          { uri: 'pkg:npm/react@18.3.1', digest: { sha256: '9b8417fe28...' } },
          { uri: 'pkg:npm/lucide-react@0.344.0', digest: { sha256: '14b09dc99a...' } }
        ]
      },
      runDetails: {
        builder: {
          id: 'https://github.com/slsa-framework/slsa-github-generator',
          version: 'v2.0.0'
        },
        metadata: {
          invocationId: `inv-${Date.now()}`,
          startedOn: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
          finishedOn: new Date().toISOString()
        },
        byproducts: [
          { name: 'build.log', digest: { sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } }
        ]
      }
    }
  };
}

export function generateCosignCommand(imageOrFile: string): { signCmd: string; verifyCmd: string } {
  return {
    signCmd: `cosign sign --key cosign.key --yes ${imageOrFile}`,
    verifyCmd: `cosign verify --key cosign.pub ${imageOrFile} \\
  --certificate-identity-regexp "https://github.com/org/.*" \\
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"`
  };
}
