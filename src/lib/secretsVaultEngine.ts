/**
 * Secrets Vault & KMS Manager Engine
 * Emulates HashiCorp Vault, AWS KMS envelope encryption, ephemeral secrets,
 * TTL management, secret leases, and automated key rotation.
 */

export interface VaultSecretItem {
  id: string;
  path: string; // e.g. "secret/data/production/database"
  key: string;
  version: number;
  isEphemeral: boolean;
  ttlSeconds?: number;
  expiresAt?: string;
  kmsKeyId: string;
  algorithm: 'AES-256-GCM' | 'CHACHA20-POLY1305' | 'RSA-4096';
  accessPolicy: 'READ_ONLY' | 'ADMIN' | 'DEV_SECOPS';
  lastRotated: string;
  isLeakedInRepo?: boolean;
}

export interface KmsMasterKey {
  keyId: string;
  alias: string;
  state: 'Enabled' | 'Disabled' | 'PendingDeletion';
  keyUsage: 'ENCRYPT_DECRYPT' | 'SIGN_VERIFY';
  origin: 'AWS_KMS' | 'VAULT_TRANSIT' | 'GCP_CLOUD_KMS';
  rotationPeriodDays: number;
  nextRotationDate: string;
}

export const DEFAULT_KMS_KEYS: KmsMasterKey[] = [
  {
    keyId: 'arn:aws:kms:us-east-1:123456789012:key/secscan-master-kms-01',
    alias: 'alias/secscan/production-master',
    state: 'Enabled',
    keyUsage: 'ENCRYPT_DECRYPT',
    origin: 'AWS_KMS',
    rotationPeriodDays: 90,
    nextRotationDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 45).toISOString().split('T')[0]
  },
  {
    keyId: 'vault-transit-key-tokens-02',
    alias: 'transit/keys/jwt-and-tokens',
    state: 'Enabled',
    keyUsage: 'SIGN_VERIFY',
    origin: 'VAULT_TRANSIT',
    rotationPeriodDays: 30,
    nextRotationDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 12).toISOString().split('T')[0]
  }
];

export const DEFAULT_VAULT_SECRETS: VaultSecretItem[] = [
  {
    id: 'sec-db-prod',
    path: 'secret/data/prod/postgres',
    key: 'DB_PASSWORD',
    version: 3,
    isEphemeral: false,
    kmsKeyId: 'alias/secscan/production-master',
    algorithm: 'AES-256-GCM',
    accessPolicy: 'DEV_SECOPS',
    lastRotated: new Date(Date.now() - 1000 * 60 * 60 * 24 * 14).toISOString().split('T')[0],
    isLeakedInRepo: false
  },
  {
    id: 'sec-aws-access',
    path: 'secret/data/aws/deployer',
    key: 'AWS_SECRET_ACCESS_KEY',
    version: 5,
    isEphemeral: true,
    ttlSeconds: 3600,
    expiresAt: new Date(Date.now() + 1000 * 60 * 42).toLocaleTimeString(),
    kmsKeyId: 'alias/secscan/production-master',
    algorithm: 'AES-256-GCM',
    accessPolicy: 'ADMIN',
    lastRotated: new Date().toISOString().split('T')[0],
    isLeakedInRepo: true
  },
  {
    id: 'sec-slack-bot',
    path: 'secret/data/integrations/slack',
    key: 'SLACK_BOT_OAUTH_TOKEN',
    version: 1,
    isEphemeral: false,
    kmsKeyId: 'transit/keys/jwt-and-tokens',
    algorithm: 'CHACHA20-POLY1305',
    accessPolicy: 'READ_ONLY',
    lastRotated: new Date(Date.now() - 1000 * 60 * 60 * 24 * 60).toISOString().split('T')[0],
    isLeakedInRepo: true
  }
];

export function generateEphemeralSecret(path: string, key: string, ttlMinutes: number = 60): VaultSecretItem {
  return {
    id: `sec-ephem-${Date.now()}`,
    path,
    key,
    version: 1,
    isEphemeral: true,
    ttlSeconds: ttlMinutes * 60,
    expiresAt: new Date(Date.now() + 1000 * 60 * ttlMinutes).toLocaleTimeString(),
    kmsKeyId: 'alias/secscan/production-master',
    algorithm: 'AES-256-GCM',
    accessPolicy: 'DEV_SECOPS',
    lastRotated: new Date().toISOString().split('T')[0],
    isLeakedInRepo: false
  };
}

export function generateVaultClientSnippet(secretPath: string, keyName: string): string {
  return `import { VaultClient } from '@vault/sdk';

const vault = new VaultClient({
  endpoint: process.env.VAULT_ADDR || 'https://vault.internal.corp:8200',
  token: process.env.VAULT_TOKEN
});

// Leitura dinâmica segura com Envelope Encryption e TTL
export async function getDecryptedSecret() {
  const secret = await vault.kv2.read({
    mount: 'secret',
    path: '${secretPath}'
  });
  return secret.data.data.${keyName};
}
`;
}
