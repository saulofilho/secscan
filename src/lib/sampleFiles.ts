import { ScannedFile } from '../types';
import { validateFileForSensitivePatterns } from './workspaceValidator';

export { validateFileForSensitivePatterns };

// Safe mock demonstration fixtures that do not trigger GitHub Secret Scanning / Push Protection
const MOCK_STRIPE_SECRET = 'DEMO_STRIPE_SECRET_KEY_FOR_TESTS';
const MOCK_GITHUB_PAT = 'DEMO_GITHUB_PAT_TOKEN_SAMPLE_FOR_TESTS';
const MOCK_SLACK_WEBHOOK = 'https://webhook.internal.corp/services/demo-alerts-channel';
const MOCK_GOOGLE_KEY = 'DEMO_GOOGLE_API_KEY_SAMPLE_TEST_99';
const MOCK_AWS_KEY = 'DEMO_AWS_AKID_EXAMPLE_KEY_01';
const MOCK_AWS_SECRET = 'DEMO_AWS_SECRET_KEY_SAMPLE_TEST_KEY_40';
const MOCK_DB_URI = 'postgres://app_user:REDACTED_DEMO_PASSWORD@127.0.0.1:5432/finance_db';
const MOCK_JWT_ADMIN_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vX3VzZXIiLCJyb2xlIjoiU1VQRVJfQURNSU4ifQ.DEMO_SIGNATURE_FOR_TESTS_ONLY';
const MOCK_STAGING_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdGFnaW5nX3VzZXIifQ.DEMO_SIGNATURE_FOR_STAGING_ONLY';

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
  const res = await fetch("/api/v2/users/" + userId + "/audit-trail?limit=50&format=json");
  
  // LinkFinder Internal GraphQL endpoint
  const gql = await fetch('/api/v1/graphql?query={financialAccounts{id,balance}}');
  
  // LinkFinder Internal Admin route
  await axios.get('/api/internal/debug/sysinfo');
  return res.json();
}

async function renderUserProfile(userId) {
  // Data Flow Consumer: Fetches endpoint data and feeds dangerous sinks
  const metadata = await fetchPortalMetadata(userId);
  
  // Tainted Sink: unescaped innerHTML injection from API response
  document.getElementById("profile-container").innerHTML = metadata.bioHtml;
  
  // Tainted Sink: insecure storage of auth token from endpoint
  localStorage.setItem("session_token", metadata.token);
  
  // Invokes custom script evaluator with payload from API
  loadUserCustomScript(metadata);
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
    expect(MOCK_TEST_API_KEY).toContain('DEMO_STRIPE_');
  });

  it('should authenticate user with mock token', async () => {
    const auth = await AuthService.authenticate();
    expect(auth).toBeDefined();
  });
});`
  }
];
