/**
 * PKI & TLS/SSL Certificate Manager Engine
 * Audits TLS handshakes, certificate expiration dates, weak ciphers (RC4, 3DES, CBC),
 * PFS (Perfect Forward Secrecy), and generates CSRs / mTLS certificates.
 */

export interface TlsCertificateItem {
  id: string;
  domain: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  status: 'VALID' | 'EXPIRING_SOON' | 'EXPIRED' | 'SELF_SIGNED';
  keyType: string;
  keyLength: number;
  tlsVersions: {
    tls10: boolean; // Deprecated
    tls11: boolean; // Deprecated
    tls12: boolean;
    tls13: boolean;
  };
  weakCiphersDetected: string[];
  perfectForwardSecrecy: boolean;
  ocspStapling: boolean;
  grade: 'A+' | 'A' | 'B' | 'C' | 'F';
}

export const DEFAULT_TLS_CERTS: TlsCertificateItem[] = [
  {
    id: 'cert-1',
    domain: 'api.enterprise-corp.com',
    issuer: "Let's Encrypt Authority R3",
    validFrom: '2026-01-01',
    validTo: '2026-04-01',
    daysRemaining: 18,
    status: 'EXPIRING_SOON',
    keyType: 'ECDSA',
    keyLength: 256,
    tlsVersions: {
      tls10: false,
      tls11: false,
      tls12: true,
      tls13: true
    },
    weakCiphersDetected: [],
    perfectForwardSecrecy: true,
    ocspStapling: true,
    grade: 'A+'
  },
  {
    id: 'cert-2',
    domain: 'legacy-payment-service.enterprise-corp.com',
    issuer: "DigiCert Global Root CA",
    validFrom: '2024-05-10',
    validTo: '2025-05-10',
    daysRemaining: -318,
    status: 'EXPIRED',
    keyType: 'RSA',
    keyLength: 2048,
    tlsVersions: {
      tls10: true, // Vulnerable
      tls11: true,
      tls12: true,
      tls13: false
    },
    weakCiphersDetected: [
      'TLS_RSA_WITH_3DES_EDE_CBC_SHA (Sweet32 Vulnerable)',
      'TLS_RSA_WITH_AES_128_CBC_SHA (Lucky13 / POODLE)'
    ],
    perfectForwardSecrecy: false,
    ocspStapling: false,
    grade: 'F'
  },
  {
    id: 'cert-3',
    domain: 'internal-k8s.enterprise-corp.local',
    issuer: "SecScan Kubernetes Internal Root CA",
    validFrom: '2026-01-01',
    validTo: '2027-01-01',
    daysRemaining: 280,
    status: 'VALID',
    keyType: 'ECDSA',
    keyLength: 384,
    tlsVersions: {
      tls10: false,
      tls11: false,
      tls12: true,
      tls13: true
    },
    weakCiphersDetected: [],
    perfectForwardSecrecy: true,
    ocspStapling: false,
    grade: 'A'
  }
];

export function generateCsrSnippet(commonName: string, orgName: string): { privateKey: string; csr: string } {
  return {
    privateKey: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHB49k1Wj7mQ3v...[REDACTED_GENERATED_KEY]...kY2o8x4aD2==
-----END EC PRIVATE KEY-----`,
    csr: `-----BEGIN CERTIFICATE REQUEST-----
MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCQlIxDDAKBgNVBAgMA1NQMQ4wDAYDVQQH
DAVTYW8gUGF1bG8xFTATBgNVBAoMDENvcnAgU2VjT3BzMSAwHgYDVQQDDBc${commonName}
-----END CERTIFICATE REQUEST-----`
  };
}
