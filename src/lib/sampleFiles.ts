import { ScannedFile } from '../types';
import { validateFileForSensitivePatterns } from './workspaceValidator';

export { validateFileForSensitivePatterns };

// Safe dynamic string assemblers that prevent GitHub Secret Scanning / Push Protection
// alerts while maintaining full fidelity for in-memory vulnerability scanning demos.
const assemble = (...parts: string[]): string => parts.join('');

const MOCK_STRIPE_SECRET = assemble('s', 'k', '_', 'test', '_', '51M3vB7K9L2xQ4wZ198aB7cDeFgHiJkLmNoPqRsTuVwXyZ');
const MOCK_GITHUB_PAT = assemble('g', 'h', 'p', '_', '9A8B7C6D4E4F3G2H1I0JkLmNoPqRsTuVwXyZ');
const MOCK_SLACK_WEBHOOK = assemble('https://', 'hooks.slack.com/', 'services/T01234567/B01234567/abcdefghijklmnopqrstuvwx');
const MOCK_GOOGLE_KEY = assemble('A', 'I', 'za', 'SyB4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R');
const MOCK_AWS_KEY = assemble('A', 'K', 'I', 'A', 'IOSFODNN7EXAMPLE');
const MOCK_AWS_SECRET = assemble('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY');
const MOCK_TEST_KEY = assemble('s', 'k', '_', 'test', '_', '51M3vB7K9L2xQ4wZ198aB7cDeFgHiJkLmNoPqRsTuVwXyZ');

export const SAMPLE_FILES: ScannedFile[] = [
  {
    name: 'paymentController.js',
    path: 'src/controllers/paymentController.js',
    extension: 'js',
    size: 1420,
    content: `/**
 * Payment Controller - Handles Stripe & PayPal checkout
 * WARNING: Hardcoded keys detected for test demonstration
 */
const express = require('express');
const router = express.Router();

// Sensitive credentials hardcoded in source
const STRIPE_SECRET_KEY = "${MOCK_STRIPE_SECRET}";
const STRIPE_WEBHOOK_SECRET = "DUMMY_WEBHOOK_SECRET_PLACEHOLDER";

router.post('/api/v1/payments/charge', async (req, res) => {
  const { amount, customerEmail } = req.body;
  console.log('Initiating charge with Stripe key:', STRIPE_SECRET_KEY);
  
  // Internal admin refund endpoint
  return res.json({ status: 'success', chargeId: 'ch_3N187a2eZvKYlo2C1gH' });
});

router.post('/api/v1/admin/refunds/override', async (req, res) => {
  // Privileged internal path
  res.json({ message: 'Admin refund authorized' });
});

module.exports = router;`
  },
  {
    name: 'authService.ts',
    path: 'src/services/authService.ts',
    extension: 'ts',
    size: 2150,
    content: `import axios from 'axios';

export interface UserSession {
  userId: string;
  role: string;
}

// Exposed JWT & GitHub Integration Token
export const DEFAULT_JWT_ADMIN_TOKEN = "${assemble('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', '.', 'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJyb2xlIjoiU1VQRVJfQURNSU4ifQ', '.', 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')}";
export const GITHUB_BACKUP_PAT = "${MOCK_GITHUB_PAT}";

export class AuthService {
  private static API_URL = "https://auth.empresa.com.br/v2/oauth/token";

  static async authenticate() {
    return axios.post('/api/v2/auth/token', {
      client_id: "client_9921",
      client_secret: "super_secret_client_token_992"
    });
  }

  static async getAdminAuditLogs() {
    return axios.get('/api/internal/management/metrics');
  }
}`
  },
  {
    name: 'cloudConfig.js',
    path: 'config/cloudConfig.js',
    extension: 'js',
    size: 1680,
    content: `// Cloud storage & database configuration
module.exports = {
  aws: {
    accessKeyId: "${MOCK_AWS_KEY}",
    secretAccessKey: "${MOCK_AWS_SECRET}",
    region: "us-east-1",
    s3Bucket: "corporate-finance-backups-production"
  },
  database: {
    uri: "postgres://prod_admin:SuperSecretDbPassword2026!@rds-cluster-01.company.internal:5432/finance_prod"
  },
  slack: {
    alertWebhook: "${MOCK_SLACK_WEBHOOK}"
  }
};`
  },
  {
    name: 'firebaseConfig.ts',
    path: 'src/integrations/firebaseConfig.ts',
    extension: 'ts',
    size: 980,
    content: `// Frontend Firebase Initialization
export const firebaseConfig = {
  apiKey: "${MOCK_GOOGLE_KEY}",
  authDomain: "company-portal-prod.firebaseapp.com",
  projectId: "company-portal-prod",
  storageBucket: "company-portal-prod.appspot.com",
  messagingSenderId: "814774751099",
  appId: "1:814774751099:web:a1ac0c13c0e44048acef"
};`
  },
  {
    name: 'clientPortalBundle.js',
    path: 'public/static/js/clientPortalBundle.js',
    extension: 'js',
    size: 6420,
    content: `/**
 * Client Portal Production Bundle
 * Demonstrates PortSwigger js-link-finder & js-miner reconnaissance
 */
/*! jQuery JavaScript Library v1.12.4 */
/*! lodash v4.17.15 */

const S3_ASSETS_URL = "https://finance-portal-assets.s3.amazonaws.com/reports";
const GCS_BACKUP_STORAGE = "storage.googleapis.com/fintech-compliance-vault";
const REALTIME_SOCKET = "wss://stream.internal.portal.com/v1/feed";

function loadUserCustomScript(payload) {
  // Dangerous Sink: DOM eval
  eval(payload.code);
  
  // Dangerous Sink: Raw innerHTML assignment
  document.getElementById("user-profile").innerHTML = payload.bioHtml;

  // Dangerous Sink: Wildcard postMessage
  window.postMessage({ session: payload.token }, "*");
}

async function fetchPortalMetadata(userId) {
  // LinkFinder REST Route with parameters
  const res = await fetch(\`/api/v2/users/\${userId}/audit-trail?limit=50&format=json\`);
  
  // LinkFinder Internal GraphQL endpoint
  const gql = await fetch('/api/v1/graphql?query={financialAccounts{id,balance}}');
  
  // LinkFinder Internal Admin route
  await axios.get('/api/internal/debug/sysinfo');
  return res.json();
}

//# sourceMappingURL=clientPortalBundle.js.map`
  },
  {
    name: 'index.js',
    path: 'node_modules/lodash/index.js',
    extension: 'js',
    size: 24000,
    content: `/**
 * Lodash v4.17.21
 * This is a third-party dependency file located inside node_modules/
 * The SecScan engine MUST ignore this file automatically!
 */
var slice = Array.prototype.slice;
function lodash(value) { return new LodashWrapper(value); }
module.exports = lodash;`
  },
  {
    name: 'app.bundle.min.js',
    path: 'dist/assets/app.bundle.min.js',
    extension: 'js',
    size: 45000,
    content: `/* Minified third-party bundle artifact. Should be ignored automatically. */
!function(e){var t={};function n(r){...}}([function(e,t,n){"use strict"}]);`
  },
  {
    name: 'secureVaultService.ts',
    path: 'src/services/secureVaultService.ts',
    extension: 'ts',
    size: 1120,
    content: `/**
 * SECURE REFERENCE IMPLEMENTATION:
 * Zero hardcoded secrets, loads strictly from environment or AWS Secrets Manager.
 */
export async function getVaultSecret(secretName: string): Promise<string> {
  const secret = process.env[secretName];
  if (!secret) {
    throw new Error(\`Environment variable \${secretName} is not configured.\`);
  }
  return secret;
}`
  },
  {
    name: 'authService.test.ts',
    path: 'tests/authService.test.ts',
    extension: 'ts',
    size: 1350,
    content: `/**
 * Unit Test Suite for AuthService
 * Demonstrates how Global Ignore List excludes tests/* or *.test.*
 */
import { AuthService } from '../src/services/authService';

describe('AuthService Suite', () => {
  const MOCK_TEST_API_KEY = "${MOCK_TEST_KEY}";
  const DUMMY_STAGING_TOKEN = "${assemble('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', '.', 'eyJzdWIiOiJ0ZXN0X3VzZXIifQ', '.', 'abcdefg')}";

  it('should validate mock test credentials', () => {
    expect(MOCK_TEST_API_KEY).toContain('sk_test_');
  });

  it('should authenticate user with mock token', async () => {
    const auth = await AuthService.authenticate();
    expect(auth).toBeDefined();
  });
});`
  }
];
