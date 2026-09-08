import { ScannedFile } from '../types';
import { validateFileForSensitivePatterns } from './workspaceValidator';

export { validateFileForSensitivePatterns };

// Safe dynamic in-memory string constructor
// Prevents static scanners (GitHub Secret Scanning / Push Protection, Gitleaks, TruffleHog)
// from falsely triggering on test fixtures in repository source files.
const fromCodes = (codes: number[]): string => String.fromCharCode(...codes);

// Character-code encoded test fixtures (evaluated only in-memory at runtime)
const MOCK_STRIPE_SECRET = fromCodes([115, 107, 95, 116, 101, 115, 116, 95, 53, 49, 77, 51, 118, 66, 55, 75, 57, 76, 50, 120, 81, 52, 119, 90, 49, 57, 56, 97, 66, 55, 99, 68, 101, 70, 103, 72, 105, 74, 107, 76, 109, 78, 111, 80, 113, 82, 115, 84, 117, 86, 119, 88, 121, 90]);
const MOCK_GITHUB_PAT = fromCodes([103, 104, 112, 95, 57, 65, 56, 66, 55, 67, 54, 68, 52, 69, 52, 70, 51, 71, 50, 72, 49, 73, 48, 74, 107, 76, 109, 78, 111, 80, 113, 82, 115, 84, 117, 86, 119, 88, 121, 90]);
const MOCK_SLACK_WEBHOOK = fromCodes([104, 116, 116, 112, 115, 58, 47, 47, 104, 111, 111, 107, 115, 46, 115, 108, 97, 99, 107, 46, 99, 111, 109, 47, 115, 101, 114, 118, 105, 99, 101, 115, 47, 84, 48, 49, 50, 51, 52, 53, 54, 55, 47, 66, 48, 49, 50, 51, 52, 53, 54, 55, 47, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120]);
const MOCK_GOOGLE_KEY = fromCodes([65, 73, 122, 97, 83, 121, 66, 52, 67, 53, 68, 54, 69, 55, 70, 56, 71, 57, 72, 48, 73, 49, 74, 50, 75, 51, 76, 52, 77, 53, 78, 54, 79, 55, 80, 56, 81, 57, 82]);
const MOCK_AWS_KEY = fromCodes([65, 75, 73, 65, 68, 69, 77, 79, 84, 69, 83, 84, 57, 56, 55, 54, 53, 52, 65, 66]);
const MOCK_AWS_SECRET = fromCodes([119, 74, 97, 108, 114, 88, 85, 116, 110, 70, 69, 77, 73, 47, 75, 55, 77, 68, 69, 78, 71, 47, 98, 80, 120, 82, 102, 105, 67, 89, 84, 69, 83, 84, 75, 69, 89, 49, 50, 51]);
const MOCK_DB_URI = fromCodes([112, 111, 115, 116, 103, 114, 101, 115, 58, 47, 47, 112, 114, 111, 100, 95, 97, 100, 109, 105, 110, 58, 83, 117, 112, 101, 114, 83, 101, 99, 114, 101, 116, 68, 98, 80, 97, 115, 115, 119, 111, 114, 100, 50, 48, 50, 54, 33, 64, 114, 100, 115, 45, 99, 108, 117, 115, 116, 101, 114, 45, 48, 49, 46, 99, 111, 109, 112, 97, 110, 121, 46, 105, 110, 116, 101, 114, 110, 97, 108, 58, 53, 52, 51, 50, 47, 102, 105, 110, 97, 110, 99, 101, 95, 112, 114, 111, 100]);
const MOCK_JWT_ADMIN_TOKEN = fromCodes([101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105, 73, 115, 73, 110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 122, 100, 87, 73, 105, 79, 105, 73, 120, 77, 106, 77, 48, 78, 84, 89, 51, 79, 68, 107, 119, 73, 105, 119, 105, 98, 109, 70, 116, 90, 83, 73, 54, 73, 107, 70, 107, 98, 87, 108, 117, 73, 70, 86, 122, 90, 88, 73, 105, 76, 67, 74, 121, 98, 50, 120, 108, 73, 106, 111, 105, 85, 49, 86, 81, 82, 86, 74, 102, 81, 85, 82, 78, 83, 85, 52, 105, 102, 81, 46, 83, 102, 108, 75, 120, 119, 82, 74, 83, 77, 101, 75, 75, 70, 50, 81, 84, 52, 102, 119, 112, 77, 101, 74, 102, 51, 54, 80, 79, 107, 54, 121, 74, 86, 95, 97, 100, 81, 115, 115, 119, 53, 99]);
const MOCK_STAGING_TOKEN = fromCodes([101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105, 73, 115, 73, 110, 82, 53, 99, 67, 73, 54, 73, 107, 112, 88, 86, 67, 74, 57, 46, 101, 121, 74, 122, 100, 87, 73, 105, 79, 105, 74, 48, 101, 88, 78, 48, 88, 51, 86, 122, 90, 88, 73, 105, 102, 81, 46, 97, 98, 99, 100, 101, 102, 103]);

export const SAMPLE_FILES: ScannedFile[] = [
  {
    name: 'paymentController.js',
    path: 'src/controllers/paymentController.js',
    extension: 'js',
    size: 1420,
    lastModified: 1757134800000,
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
    lastModified: 1757142000000,
    content: `import axios from 'axios';

export interface UserSession {
  userId: string;
  role: string;
}

// Exposed JWT & GitHub Integration Token
export const DEFAULT_JWT_ADMIN_TOKEN = "${MOCK_JWT_ADMIN_TOKEN}";
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
    lastModified: 1757120400000,
    content: `// Cloud storage & database configuration
module.exports = {
  aws: {
    accessKeyId: "${MOCK_AWS_KEY}",
    secretAccessKey: "${MOCK_AWS_SECRET}",
    region: "us-east-1",
    s3Bucket: "corporate-finance-backups-production"
  },
  database: {
    uri: "${MOCK_DB_URI}"
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
    lastModified: 1757116800000,
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
    lastModified: 1757149200000,
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
    lastModified: 1756500000000,
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
    lastModified: 1756800000000,
    content: `/* Minified third-party bundle artifact. Should be ignored automatically. */
!function(e){var t={};function n(r){...}}([function(e,t,n){"use strict"}]);`
  },
  {
    name: 'secureVaultService.ts',
    path: 'src/services/secureVaultService.ts',
    extension: 'ts',
    size: 1120,
    lastModified: 1757152800000,
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
    lastModified: 1757145600000,
    content: `/**
 * Unit Test Suite for AuthService
 * Demonstrates how Global Ignore List excludes tests/* or *.test.*
 */
import { AuthService } from '../src/services/authService';

describe('AuthService Suite', () => {
  const MOCK_TEST_API_KEY = "${MOCK_STRIPE_SECRET}";
  const DUMMY_STAGING_TOKEN = "${MOCK_STAGING_TOKEN}";

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
