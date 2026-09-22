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
    name: 'encryptionService.js',
    path: 'src/services/encryptionService.js',
    extension: 'js',
    size: 1540,
    lastModified: 1757138400000,
    content: `/**
 * Legacy Cryptography Service
 * WARNING: Uses deprecated crypto libraries, MD5 hashing, and weak PRNG
 */
const crypto = require('crypto');

// Insecure Hashing: MD5 for password storage (Vulnerable to rainbow tables & collisions)
function hashUserPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Insecure Cipher: createCipher with ECB mode and no initialization vector (IV)
function encryptSensitivePayload(plaintext, secretKey) {
  const cipher = crypto.createCipher('aes-128-ecb', secretKey);
  let crypted = cipher.update(plaintext, 'utf8', 'hex');
  crypted += cipher.final('hex');
  return crypted;
}

// Insecure PRNG: Math.random() for authentication tokens and reset pins
function generateSessionResetToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

module.exports = {
  hashUserPassword,
  encryptSensitivePayload,
  generateSessionResetToken
};`
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
  },
  {
    name: 'package.json',
    path: 'package.json',
    extension: 'json',
    size: 1850,
    lastModified: 1757156400000,
    content: `{
  "name": "fintech-portal-api",
  "version": "1.4.2",
  "description": "Enterprise Financial Core & Payment API",
  "main": "src/controllers/paymentController.js",
  "license": "Proprietary",
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.15",
    "axios": "0.21.1",
    "jsonwebtoken": "8.5.1",
    "minimist": "1.2.5",
    "cors": "2.8.5",
    "dotenv": "16.0.3",
    "pg": "8.11.0",
    "gpl-crypto-tools": "2.1.0"
  },
  "devDependencies": {
    "jest": "29.5.0",
    "supertest": "6.3.3",
    "typescript": "5.0.4"
  }
}`
  },
  {
    name: 'Dockerfile',
    path: 'Dockerfile',
    extension: 'dockerfile',
    size: 920,
    lastModified: 1757156800000,
    content: `# Insecure Dockerfile Configuration Example
FROM node:latest

WORKDIR /app

# Insecure: Installing SSH and sudo in application container
RUN apt-get update && apt-get install -y openssh-server sudo curl

COPY package*.json ./
RUN npm install

COPY . .

# Insecure: Sensitive ports exposed (SSH 22 & App 3000)
EXPOSE 22 3000

# Insecure: Running container process as root without USER directive
CMD ["npm", "start"]`
  },
  {
    name: 'docker-compose.yml',
    path: 'docker-compose.yml',
    extension: 'yml',
    size: 1150,
    lastModified: 1757157200000,
    content: `version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
      - "22:22"
    environment:
      - NODE_ENV=production
      - DB_PASSWORD=unmasked_postgres_admin_pass
    volumes:
      # Insecure host docker socket mount
      - /var/run/docker.sock:/var/run/docker.sock
    privileged: true

  database:
    image: postgres:latest
    ports:
      # Insecure: Database exposed to all interfaces
      - "0.0.0.0:5432:5432"
    environment:
      POSTGRES_USER: app_user
      POSTGRES_PASSWORD: super_insecure_db_pass_123
      POSTGRES_DB: finance_db`
  },
  {
    name: 'deployment.yaml',
    path: 'k8s/deployment.yaml',
    extension: 'yaml',
    size: 1420,
    lastModified: 1757157600000,
    content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: fintech-portal-deployment
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fintech-portal
  template:
    metadata:
      labels:
        app: fintech-portal
    spec:
      containers:
      - name: api-container
        image: company/fintech-portal:latest
        securityContext:
          # Insecure K8s misconfiguration: privileged container
          privileged: true
          allowPrivilegeEscalation: true
          readOnlyRootFilesystem: false
        # Insecure: Missing resources requests & limits (DoS risk)
        ports:
        - containerPort: 3000
        volumeMounts:
        - name: host-root
          mountPath: /host-system
      volumes:
      - name: host-root
        hostPath:
          path: /`
  },
  {
    name: 'ci-deploy.yml',
    path: '.github/workflows/ci-deploy.yml',
    extension: 'yml',
    size: 980,
    lastModified: 1757158000000,
    content: `name: Production CI/CD Pipeline

on:
  # Insecure: pull_request_target triggers with write access on external PRs
  pull_request_target:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3
        with:
          ref: \${{ github.event.pull_request.head.sha }}

      # Insecure script injection from untrusted PR title
      - name: Print PR Summary
        run: |
          echo "Processing PR: \${{ github.event.pull_request.title }}"

      - name: Deploy to Cloud
        env:
          PROD_DEPLOY_KEY: \${{ secrets.PROD_AWS_KEY }}
        run: |
          npm run build
          echo "Deployed successfully"`
  },
  {
    name: 'main.tf',
    path: 'terraform/main.tf',
    extension: 'tf',
    size: 1650,
    lastModified: 1757158400000,
    content: `# Infrastructure as Code - Cloud Production Stack
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Insecure Security Group: Open to all internet on SSH & DB
resource "aws_security_group" "allow_all_ingress" {
  name        = "production-web-sg"
  description = "Security Group com regras de entrada irrestritas"

  ingress {
    description = "SSH from anywhere (RISK: CRITICAL)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "PostgreSQL Database public access"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Insecure S3 Bucket: Missing KMS Customer Encryption
resource "aws_s3_bucket" "financial_reports" {
  bucket = "corp-financial-vault-q3"
  
  versioning {
    enabled = false
  }

  tags = {
    Environment = "production"
    DataClass   = "Confidential"
  }
}

# Insecure RDS Database: Public IP exposed
resource "aws_db_instance" "production_postgres" {
  identifier          = "corp-finance-pg-cluster"
  allocated_storage   = 100
  engine              = "postgres"
  engine_version      = "15.3"
  instance_class      = "db.t4g.xlarge"
  username            = "pgadmin"
  password            = "temp_admin_pass_replace_me"
  publicly_accessible = true
  skip_final_snapshot = true
}`
  }
];
