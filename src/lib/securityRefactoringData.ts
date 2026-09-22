import { SecurityRefactoringRecipe, ScannedFile, ScanFinding } from '../types';

export const REFACTORING_RECIPES: SecurityRefactoringRecipe[] = [
  // 1. Insecure Cryptography: Broken Hashing (MD5 / SHA-1) -> Modern Argon2id / bcrypt
  {
    id: 'crypto-md5-to-argon2',
    title: 'Substituição de Hashing Inseguro (MD5 / SHA-1) por Argon2id',
    category: 'CRYPTOGRAPHY',
    severity: 'CRITICAL',
    cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
    cweUrl: 'https://cwe.mitre.org/data/definitions/327.html',
    owasp: 'A02:2021 - Cryptographic Failures',
    owaspUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    cvssReduction: { before: 9.1, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'crypto.createHash("md5") / crypto-js (MD5)',
    modernReplacement: 'argon2 (Argon2id Winner of PHC) / node:crypto.scrypt',
    shortSummary: 'MD5 e SHA-1 são vulneráveis a colisões instantâneas e rainbow tables. Substitua por funções de derivação lentas resistentes a GPU (Argon2id).',
    vulnerabilityExplanation: 'Algoritmos de digest rápido como MD5 e SHA-1 foram projetados para integridade de checksums, não para senhas ou dados sensíveis. Um invasor com placas de vídeo comuns pode testar bilhões de hashes MD5 por segundo com tabelas rainbow precomputadas ou ataques de força bruta direta.',
    modernSolutionExplanation: 'Argon2id é o padrão ouro de hashing moderno (vencedor da Password Hashing Competition), combinando resistência contra ataques de canal lateral (Argon2i) e ataques baseados em GPU/ASIC com alto custo de memória (Argon2d). Alternativamente, utilize scrypt nativo do Node.js.',
    prerequisites: [
      'npm install argon2',
      'Node.js >= 16.0.0 (suporte a buffers nativos de 64-bit)'
    ],
    breakingChangesWarning: 'Argon2id é assíncrono (Promise-based) e inclui automaticamente salt criptográfico seguro de 16 bytes no hash resultante. Substitua chamadas síncronas por await.',
    beforeCode: `// ❌ INSEGURO: MD5 sem salt e sem resistência a força bruta
const crypto = require('crypto');

function hashUserPassword(password) {
  // Vulnerabilidade: MD5 pode ser revertido em milissegundos via rainbow tables
  return crypto.createHash('md5').update(password).digest('hex');
}

function verifyPassword(inputPassword, storedHash) {
  // Vulnerável a timing attacks e colisões
  return hashUserPassword(inputPassword) === storedHash;
}`,
    afterCode: `// ✅ SEGURO: Argon2id moderno com custo de memória e salt automático
import * as argon2 from 'argon2';

export async function hashUserPassword(password: string): Promise<string> {
  // Argon2id com parâmetros recomendados pela OWASP
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64 MB de memória
    timeCost: 3,         // 3 iterações de processamento
    parallelism: 1       // 1 thread dedicada
  });
}

export async function verifyPassword(inputPassword: string, storedHash: string): Promise<boolean> {
  // Comparação em tempo constante (constant-time) imune a timing attacks
  try {
    return await argon2.verify(storedHash, inputPassword);
  } catch (err) {
    return false;
  }
}`,
    unifiedDiff: `--- src/services/authService.js (Legacy MD5)
+++ src/services/authService.ts (Modern Argon2id)
@@ -1,13 +1,21 @@
-// ❌ INSEGURO: MD5 sem salt e sem resistência a força bruta
-const crypto = require('crypto');
+// ✅ SEGURO: Argon2id moderno com custo de memória e salt automático
+import * as argon2 from 'argon2';
 
-function hashUserPassword(password) {
-  // Vulnerabilidade: MD5 pode ser revertido em milissegundos via rainbow tables
-  return crypto.createHash('md5').update(password).digest('hex');
+export async function hashUserPassword(password: string): Promise<string> {
+  // Argon2id com parâmetros recomendados pela OWASP
+  return await argon2.hash(password, {
+    type: argon2.argon2id,
+    memoryCost: 2 ** 16, // 64 MB de memória
+    timeCost: 3,         // 3 iterações
+    parallelism: 1
+  });
 }
 
-function verifyPassword(inputPassword, storedHash) {
-  // Vulnerável a timing attacks e colisões
-  return hashUserPassword(inputPassword) === storedHash;
+export async function verifyPassword(inputPassword: string, storedHash: string): Promise<boolean> {
+  // Comparação em tempo constante imune a timing attacks
+  try {
+    return await argon2.verify(storedHash, inputPassword);
+  } catch (err) {
+    return false;
+  }
 }`,
     fileMatchPatterns: ['createHash\\s*\\([\'"]md5[\'"]', 'createHash\\s*\\([\'"]sha1[\'"]', 'CryptoJS\\.MD5'],
     defaultTargetFileName: 'src/services/authService.ts',
     tags: ['crypto', 'hashing', 'md5', 'argon2', 'passwords', 'owasp-a02']
   },

  // 2. Insecure Cryptography: Obsolete Cipher (createCipher / ECB) -> AES-256-GCM com IV Aleatório & Auth Tag
  {
    id: 'crypto-cipher-to-aes256gcm',
    title: 'Migração de Cifras Obsoletas (createCipher / ECB) para AES-256-GCM Autenticado',
    category: 'CRYPTOGRAPHY',
    severity: 'CRITICAL',
    cwe: 'CWE-326: Inadequate Encryption Strength',
    cweUrl: 'https://cwe.mitre.org/data/definitions/326.html',
    owasp: 'A02:2021 - Cryptographic Failures',
    owaspUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    cvssReduction: { before: 8.8, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'crypto.createCipher("des" / "aes-128-ecb")',
    modernReplacement: 'node:crypto.createCipheriv("aes-256-gcm")',
    shortSummary: 'createCipher foi depreciado no Node.js por derivar chave e IV com MD5 obsoleto sem salt. Substitua por AES-256-GCM com IV de 12 bytes e tag de autenticação.',
    vulnerabilityExplanation: 'O método legado crypto.createCipher() usa uma função de derivação de chave insegura (EVP_BytesToKey) baseada em MD5 sem salt e modo ECB (Electronic Codebook) ou CBC sem autenticação de integridade (AEAD). O modo ECB não oculta padrões no texto cifrado e CBC sem HMAC permite ataques de padding oracle.',
    modernSolutionExplanation: 'AES-256-GCM (Galois/Counter Mode) é uma cifra autenticada (AEAD) recomendada pelo NIST e FIPS 140-3. Ela garante confidencialidade e integridade criptográfica simultânea através de uma tag de autenticação de 16 bytes e IV aleatório de 12 bytes (96 bits) único por mensagem.',
    prerequisites: [
      'Node.js nativo (módulo node:crypto)',
      'Chave simétrica de 256 bits (32 bytes) em CSPRNG'
    ],
    breakingChangesWarning: 'O formato do ciphertext deve agora conter [IV (12 bytes) + AuthTag (16 bytes) + EncryptedData]. Mensagens encriptadas anteriormente precisarão de script de migração.',
    beforeCode: `// ❌ INSEGURO: crypto.createCipher() depreciado com ECB e sem IV
const crypto = require('crypto');

function encryptData(text, secretPassword) {
  // createCipher deriva IV fraco internamente via MD5
  const cipher = crypto.createCipher('aes-128-ecb', secretPassword);
  let crypted = cipher.update(text, 'utf8', 'hex');
  crypted += cipher.final('hex');
  return crypted;
}

function decryptData(crypted, secretPassword) {
  const decipher = crypto.createDecipher('aes-128-ecb', secretPassword);
  let dec = decipher.update(crypted, 'hex', 'utf8');
  dec += decipher.final('utf8');
  return dec;
}`,
    afterCode: `// ✅ SEGURO: AES-256-GCM com IV único de 12 bytes e Tag de Autenticação (AEAD)
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recomendado pelo NIST para GCM
const TAG_LENGTH = 16; // 128 bits auth tag

export function encryptData(plaintext: string, key32Bytes: Buffer): { ciphertext: string } {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key32Bytes, iv);
  
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Empacota [IV + AuthTag + EncryptedData] em Base64 seguro
  const combined = Buffer.concat([iv, authTag, encrypted]);
  return { ciphertext: combined.toString('base64') };
}

export function decryptData(payloadBase64: string, key32Bytes: Buffer): string {
  const combined = Buffer.from(payloadBase64, 'base64');
  
  const iv = combined.subarray(0, IV_LENGTH);
  const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encryptedText = combined.subarray(IV_LENGTH + TAG_LENGTH);

  const decipher = createDecipheriv(ALGORITHM, key32Bytes, iv);
  decipher.setAuthTag(authTag); // Validação de integridade: lança erro se adulterado

  return decipher.update(encryptedText) + decipher.final('utf8');
}`,
    unifiedDiff: `--- src/utils/encryptionService.js (Legacy createCipher)
+++ src/utils/encryptionService.ts (Modern AES-256-GCM)
@@ -1,17 +1,33 @@
-// ❌ INSEGURO: crypto.createCipher() depreciado com ECB e sem IV
-const crypto = require('crypto');
+// ✅ SEGURO: AES-256-GCM com IV único de 12 bytes e Tag de Autenticação (AEAD)
+import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
+
+const ALGORITHM = 'aes-256-gcm';
+const IV_LENGTH = 12; // 96 bits recomendado pelo NIST para GCM
+const TAG_LENGTH = 16; // 128 bits auth tag
 
-function encryptData(text, secretPassword) {
-  const cipher = crypto.createCipher('aes-128-ecb', secretPassword);
-  let crypted = cipher.update(text, 'utf8', 'hex');
-  crypted += cipher.final('hex');
-  return crypted;
+export function encryptData(plaintext: string, key32Bytes: Buffer): { ciphertext: string } {
+  const iv = randomBytes(IV_LENGTH);
+  const cipher = createCipheriv(ALGORITHM, key32Bytes, iv);
+  
+  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
+  const authTag = cipher.getAuthTag();
+
+  const combined = Buffer.concat([iv, authTag, encrypted]);
+  return { ciphertext: combined.toString('base64') };
 }
 
-function decryptData(crypted, secretPassword) {
-  const decipher = crypto.createDecipher('aes-128-ecb', secretPassword);
-  let dec = decipher.update(crypted, 'hex', 'utf8');
-  dec += decipher.final('utf8');
-  return dec;
+export function decryptData(payloadBase64: string, key32Bytes: Buffer): string {
+  const combined = Buffer.from(payloadBase64, 'base64');
+  
+  const iv = combined.subarray(0, IV_LENGTH);
+  const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
+  const encryptedText = combined.subarray(IV_LENGTH + TAG_LENGTH);
+
+  const decipher = createDecipheriv(ALGORITHM, key32Bytes, iv);
+  decipher.setAuthTag(authTag);
+
+  return decipher.update(encryptedText) + decipher.final('utf8');
 }`,
     fileMatchPatterns: ['createCipher\\(', 'createDecipher\\(', 'aes-128-ecb', 'des-ecb'],
     defaultTargetFileName: 'src/utils/encryptionService.ts',
     tags: ['crypto', 'encryption', 'aes-256-gcm', 'createcipher', 'owasp-a02']
   },

  // 3. Insecure Cryptography: Insecure Randomness (Math.random) -> CSPRNG (crypto.randomBytes / crypto.getRandomValues)
  {
    id: 'crypto-prng-math-random-to-csprng',
    title: 'Substituição de PRNG Fraco (Math.random) por CSPRNG Criptográfico',
    category: 'CRYPTOGRAPHY',
    severity: 'HIGH',
    cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)',
    cweUrl: 'https://cwe.mitre.org/data/definitions/338.html',
    owasp: 'A02:2021 - Cryptographic Failures',
    owaspUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    cvssReduction: { before: 7.5, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'Math.random().toString(36)',
    modernReplacement: 'node:crypto.randomBytes / crypto.getRandomValues',
    shortSummary: 'Math.random() utiliza algoritmos lineares previsíveis (como Xoroshiro128+). Para tokens de autenticação, redefinição de senha ou IDs de sessão, use geradores criptograficamente seguros.',
    vulnerabilityExplanation: 'Math.random() em JavaScript V8 utiliza o gerador pseudo-aleatório xoroshiro128+ que não é resistente a previsão de estado. Com apenas 2 ou 3 saídas consecutivas, ferramentas automatizadas podem derivar a semente interna e prever todos os tokens passados e futuros gerados pelo sistema.',
    modernSolutionExplanation: 'CSPRNGs (Cryptographically Secure Pseudo-Random Number Generators) como crypto.randomBytes() no Node.js ou crypto.getRandomValues() no browser consultam a fonte de entropia do sistema operacional (/dev/urandom ou CryptGenRandom no Windows), garantindo imprevisibilidade matemática.',
    prerequisites: [
      'Node.js nativo (node:crypto) ou Web Crypto API nativa do navegador'
    ],
    beforeCode: `// ❌ INSEGURO: Math.random() para gerar tokens de redefinição de senha
function generatePasswordResetToken() {
  // Previsível: um invasor pode reconstruir a sequência do PRNG
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function generateOtpPin() {
  // Código de 6 dígitos vulnerável a predição
  return Math.floor(100000 + Math.random() * 900000).toString();
}`,
    afterCode: `// ✅ SEGURO: CSPRNG nativo com entropia de sistema e rejeição de bias
import { randomBytes, randomInt } from 'node:crypto';

export function generatePasswordResetToken(byteLength = 32): string {
  // 32 bytes = 256 bits de entropia criptográfica imune a predição
  return randomBytes(byteLength).toString('hex');
}

export function generateOtpPin(): string {
  // randomInt usa rejeição de bias do SO para distribuição uniforme verdadeira
  return randomInt(100000, 1000000).toString();
}`,
    unifiedDiff: `--- src/utils/tokenGenerator.js (Legacy Math.random)
+++ src/utils/tokenGenerator.ts (Modern CSPRNG)
@@ -1,11 +1,11 @@
-// ❌ INSEGURO: Math.random() para gerar tokens de redefinição de senha
-function generatePasswordResetToken() {
-  return Math.random().toString(36).substring(2) + Date.now().toString(36);
+// ✅ SEGURO: CSPRNG nativo com entropia de sistema e rejeição de bias
+import { randomBytes, randomInt } from 'node:crypto';
+
+export function generatePasswordResetToken(byteLength = 32): string {
+  return randomBytes(byteLength).toString('hex');
 }
 
-function generateOtpPin() {
-  return Math.floor(100000 + Math.random() * 900000).toString();
+export function generateOtpPin(): string {
+  return randomInt(100000, 1000000).toString();
 }`,
     fileMatchPatterns: ['Math\\.random\\(\\)', 'Math\\.floor\\(.*Math\\.random'],
     defaultTargetFileName: 'src/utils/tokenGenerator.ts',
     tags: ['crypto', 'csprng', 'math-random', 'tokens', 'entropy']
   },

  // 4. Insecure Cryptography: Obsolete Third-Party Crypto (crypto-js) -> Native Web Crypto / Node Crypto
  {
    id: 'crypto-cryptojs-to-node-native',
    title: 'Substituição de Bibliotecas de Terceiros Lentas (crypto-js) por Web Crypto / Node Native',
    category: 'CRYPTOGRAPHY',
    severity: 'MEDIUM',
    cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
    cweUrl: 'https://cwe.mitre.org/data/definitions/327.html',
    owasp: 'A02:2021 - Cryptographic Failures',
    owaspUrl: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    cvssReduction: { before: 6.8, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'import CryptoJS from "crypto-js"',
    modernReplacement: 'Web Crypto API (crypto.subtle) / node:crypto nativo',
    shortSummary: 'crypto-js é uma biblioteca puramente em JavaScript não mantida ativamente, sem aceleração por hardware (AES-NI) e propensa a vazamentos por canal lateral de memória.',
    vulnerabilityExplanation: 'Bibliotecas legadas em JS puro como crypto-js não utilizam as instruções de aceleração nativas da CPU (como AES-NI e SHA extensions) e alocam buffers de texto plano na memória gerenciada pelo Garbage Collector, onde podem persistir por tempo indeterminado e serem acessados por ataques de memory dump.',
    modernSolutionExplanation: 'A API Web Crypto padronizada (crypto.subtle) e o módulo node:crypto utilizam implementações compiladas em C++ (OpenSSL/BoringSSL) com aceleração de hardware e limpeza segura de buffers de chave.',
    prerequisites: [
      'Remover crypto-js: npm uninstall crypto-js @types/crypto-js'
    ],
    beforeCode: `// ❌ LEGADO: crypto-js em JavaScript puro (lento e vulnerável a memory leak)
import CryptoJS from 'crypto-js';

export function computeSha256(message: string): string {
  return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
}

export function encryptPayload(data: string, secretKey: string): string {
  return CryptoJS.AES.encrypt(data, secretKey).toString();
}`,
    afterCode: `// ✅ MODERNO: Web Crypto API universal (Node.js, Deno, Bun e Browsers modernos)
export async function computeSha256(message: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function encryptPayloadWithKey(plaintext: string, key: CryptoKey): Promise<{ iv: string; ciphertext: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );

  return {
    iv: Buffer.from(iv).toString('hex'),
    ciphertext: Buffer.from(encrypted).toString('base64')
  };
}`,
    unifiedDiff: `--- src/services/cryptoClient.ts (Legacy crypto-js)
+++ src/services/cryptoClient.ts (Modern Web Crypto API)
@@ -1,11 +1,24 @@
-// ❌ LEGADO: crypto-js em JavaScript puro (lento e vulnerável a memory leak)
-import CryptoJS from 'crypto-js';
+// ✅ MODERNO: Web Crypto API universal (Node.js, Deno, Bun e Browsers)
+export async function computeSha256(message: string): Promise<string> {
+  const encoder = new TextEncoder();
+  const data = encoder.encode(message);
+  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
+  
+  return Array.from(new Uint8Array(hashBuffer))
+    .map(b => b.toString(16).padStart(2, '0'))
+    .join('');
+}
 
-export function computeSha256(message: string): string {
-  return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
-}
-
-export function encryptPayload(data: string, secretKey: string): string {
-  return CryptoJS.AES.encrypt(data, secretKey).toString();
+export async function encryptPayloadWithKey(plaintext: string, key: CryptoKey): Promise<{ iv: string; ciphertext: string }> {
+  const iv = crypto.getRandomValues(new Uint8Array(12));
+  const encoded = new TextEncoder().encode(plaintext);
+  
+  const encrypted = await crypto.subtle.encrypt(
+    { name: 'AES-GCM', iv },
+    key,
+    encoded
+  );
+
+  return {
+    iv: Buffer.from(iv).toString('hex'),
+    ciphertext: Buffer.from(encrypted).toString('base64')
+  };
 }`,
     fileMatchPatterns: ['crypto-js', 'CryptoJS\\.'],
     defaultTargetFileName: 'src/services/cryptoClient.ts',
     tags: ['crypto', 'crypto-js', 'web-crypto', 'sha256', 'subtle']
   },

  // 5. Hardcoded Secrets -> Fail-Fast Environment Variables com Validação de Schema (Zod)
  {
    id: 'secrets-hardcoded-to-env-zod',
    title: 'Extração de Segredos Hardcoded para Variáveis de Ambiente Tipadas com Zod',
    category: 'SECRETS',
    severity: 'CRITICAL',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    cweUrl: 'https://cwe.mitre.org/data/definitions/798.html',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    owaspUrl: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    cvssReduction: { before: 9.8, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'const API_KEY = "sk_live_..."',
    modernReplacement: 'zod env validation + dotenv / cloud secret manager',
    shortSummary: 'Remova chaves estáticas do código-fonte e implemente um módulo de configuração validado que falha na inicialização se alguma chave estiver ausente.',
    vulnerabilityExplanation: 'Chaves de API, senhas de banco de dados e segredos JWT armazenados no código-fonte vazam facilmente através de pushes para repositórios públicos, forks, logs de CI/CD e imagens Docker expostas.',
    modernSolutionExplanation: 'Valide variáveis de ambiente na inicialização (Fail-Fast pattern) com schemas determinísticos (Zod). Garante que a aplicação nunca suba em estado de configuração incorreto ou inseguro.',
    prerequisites: [
      'npm install zod dotenv',
      'Adicionar .env ao .gitignore'
    ],
    beforeCode: `// ❌ INSEGURO: Chaves estáticas de produção no código
const STRIPE_SECRET_KEY = "sk_live_51N872FakeProdKey99214A";
const DATABASE_URL = "postgres://dbadmin:p@ssw0rd123@prod-db.internal:5432/corp";

export async function processCharge(amount: number) {
  // Usa chave hardcoded diretamente
  return stripeCharge(STRIPE_SECRET_KEY, amount);
}`,
    afterCode: `// ✅ SEGURO: Validação estrita de variáveis de ambiente com Zod (Fail-Fast)
import { z } from 'zod';
import 'dotenv/config';

const envSchema = z.object({
  STRIPE_SECRET_KEY: z.string().min(24).startsWith('sk_'),
  DATABASE_URL: z.string().url(),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development')
});

// Falha imediatamente na inicialização se alguma variável faltar
export const env = envSchema.parse(process.env);

export async function processCharge(amount: number) {
  return stripeCharge(env.STRIPE_SECRET_KEY, amount);
}`,
    unifiedDiff: `--- config/secrets.ts (Legacy Hardcoded)
+++ config/secrets.ts (Modern Zod Env Validation)
@@ -1,9 +1,17 @@
-// ❌ INSEGURO: Chaves estáticas de produção no código
-const STRIPE_SECRET_KEY = "sk_live_51N872FakeProdKey99214A";
-const DATABASE_URL = "postgres://dbadmin:p@ssw0rd123@prod-db.internal:5432/corp";
+// ✅ SEGURO: Validação estrita de variáveis de ambiente com Zod (Fail-Fast)
+import { z } from 'zod';
+import 'dotenv/config';
+
+const envSchema = z.object({
+  STRIPE_SECRET_KEY: z.string().min(24).startsWith('sk_'),
+  DATABASE_URL: z.string().url(),
+  NODE_ENV: z.enum(['development', 'test', 'production']).default('development')
+});
+
+export const env = envSchema.parse(process.env);
 
 export async function processCharge(amount: number) {
-  return stripeCharge(STRIPE_SECRET_KEY, amount);
+  return stripeCharge(env.STRIPE_SECRET_KEY, amount);
 }`,
     fileMatchPatterns: ['sk_live_', 'STRIPE_SECRET_KEY\\s*=\\s*[\'"][^\'"]+[\'"]'],
     defaultTargetFileName: 'config/secrets.ts',
     tags: ['secrets', 'zod', 'env', 'dotenv', 'cwe-798']
   },

  // 6. SQL Injection -> Parameterized Prepared Statements
  {
    id: 'injection-sql-string-concat-to-parameterized',
    title: 'Prevenção de SQL Injection com Consultas Parametrizadas',
    category: 'INJECTION',
    severity: 'CRITICAL',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    cweUrl: 'https://cwe.mitre.org/data/definitions/89.html',
    owasp: 'A03:2021 - Injection',
    owaspUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    cvssReduction: { before: 9.8, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'db.query("SELECT * FROM users WHERE email = \'" + email + "\'")',
    modernReplacement: 'db.query("SELECT ... WHERE email = $1", [email]) / ORM seguro',
    shortSummary: 'A interpolação direta de parâmetros de usuário em consultas SQL permite extração total do banco de dados (ex.: \' OR 1=1 --). Use placeholders parametrizados.',
    vulnerabilityExplanation: 'Concatenação de strings permite que atacantes alterem a estrutura semântica da consulta SQL, permitindo bypass de autenticação, extração de tabelas, exclusão de dados e execução remota de código no servidor de banco de dados.',
    modernSolutionExplanation: 'Placeholders ($1, ? ou parâmetros nomeados) separam a instrução de código dos dados. O motor do banco de dados compila o plano de execução previamente e trata a entrada do usuário estritamente como valor literal.',
    prerequisites: [
      'Cliente SQL compatível com placeholders (pg, mysql2, sqlite3 ou ORM)'
    ],
    beforeCode: `// ❌ INSEGURO: Concatenação de string com entrada de usuário (SQLi direto)
async function findUserByCredentials(email, rawPassword) {
  // Vulnerável a bypass: admin' OR '1'='1
  const sql = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + rawPassword + "'";
  const result = await db.query(sql);
  return result.rows[0];
}`,
    afterCode: `// ✅ SEGURO: Consulta parametrizada com placeholders nativos e validação
async function findUserByEmail(email: string) {
  // O banco de dados compila a consulta e recebe os dados separadamente
  const sql = 'SELECT id, email, password_hash, role FROM users WHERE email = $1';
  const result = await db.query(sql, [email]);
  
  if (result.rows.length === 0) return null;
  return result.rows[0];
}`,
    unifiedDiff: `--- src/models/userModel.js (Legacy String Concat)
+++ src/models/userModel.ts (Modern Parameterized Query)
@@ -1,7 +1,9 @@
-// ❌ INSEGURO: Concatenação de string com entrada de usuário (SQLi direto)
-async function findUserByCredentials(email, rawPassword) {
-  const sql = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + rawPassword + "'";
-  const result = await db.query(sql);
-  return result.rows[0];
+// ✅ SEGURO: Consulta parametrizada com placeholders nativos e validação
+async function findUserByEmail(email: string) {
+  const sql = 'SELECT id, email, password_hash, role FROM users WHERE email = $1';
+  const result = await db.query(sql, [email]);
+  
+  if (result.rows.length === 0) return null;
+  return result.rows[0];
 }`,
     fileMatchPatterns: ['SELECT\\s+.*\\+\\s*', 'INSERT\\s+INTO.*\\+'],
     defaultTargetFileName: 'src/models/userModel.ts',
     tags: ['injection', 'sqli', 'parameterized', 'database', 'cwe-89']
   },

  // 7. Cross-Site Scripting (DOM XSS): innerHTML / eval -> textContent / DOMPurify
  {
    id: 'xss-innerhtml-to-dompurify-textcontent',
    title: 'Neutralização de DOM XSS: Substituição de innerHTML por DOMPurify / textContent',
    category: 'DATA_VALIDATION',
    severity: 'HIGH',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    cweUrl: 'https://cwe.mitre.org/data/definitions/79.html',
    owasp: 'A03:2021 - Injection',
    owaspUrl: 'https://owasp.org/Top10/A03_2021-Injection/',
    cvssReduction: { before: 8.2, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'element.innerHTML = userInput / eval(payload)',
    modernReplacement: 'element.textContent = userInput / DOMPurify.sanitize(userInput)',
    shortSummary: 'Atribuir strings não confiáveis a innerHTML permite injeção de scripts maliciosos (<img onerror=...>) e roubo de sessão. Use textContent ou sanitizador estrito.',
    vulnerabilityExplanation: 'Quando dados fornecidos pelo usuário ou por endpoints externos são passados para innerHTML, o parser do navegador avalia tags <script>, atributos onload/onerror e URIs javascript:, executando código malicioso no contexto do usuário autenticado.',
    modernSolutionExplanation: 'textContent trata toda a entrada como texto literal sem passar pelo parser HTML. Para casos em que formatação rica (rich text) é realmente necessária, utilize DOMPurify com perfil restrito.',
    prerequisites: [
      'npm install dompurify @types/dompurify'
    ],
    beforeCode: `// ❌ INSEGURO: innerHTML direto permite injeção de scripts maliciosos (DOM XSS)
function renderUserProfile(containerElement, userProfile) {
  // Se userProfile.bio contiver <img src=x onerror=stealCookies()>, o script executará
  containerElement.innerHTML = "<h3>" + userProfile.name + "</h3><p>" + userProfile.bio + "</p>";
}`,
    afterCode: `// ✅ SEGURO: textContent seguro para texto puro ou DOMPurify para HTML sanitizado
import DOMPurify from 'dompurify';

export function renderUserProfile(containerElement: HTMLElement, userProfile: { name: string; bio: string }) {
  // Limpa o container
  containerElement.replaceChildren();

  // Opção 1: Criação segura de nós DOM com textContent nativo
  const heading = document.createElement('h3');
  heading.textContent = userProfile.name; // 100% imune a XSS

  // Opção 2: Se bio contiver formatação rica permitida, sanitizar estritamente
  const bioPara = document.createElement('div');
  bioPara.innerHTML = DOMPurify.sanitize(userProfile.bio, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href', 'target', 'rel']
  });

  containerElement.append(heading, bioPara);
}`,
    unifiedDiff: `--- src/views/profileView.js (Legacy innerHTML)
+++ src/views/profileView.ts (Modern DOMPurify Sanitized)
@@ -1,5 +1,18 @@
-// ❌ INSEGURO: innerHTML direto permite injeção de scripts maliciosos (DOM XSS)
-function renderUserProfile(containerElement, userProfile) {
-  containerElement.innerHTML = "<h3>" + userProfile.name + "</h3><p>" + userProfile.bio + "</p>";
+// ✅ SEGURO: textContent seguro para texto puro ou DOMPurify para HTML sanitizado
+import DOMPurify from 'dompurify';
+
+export function renderUserProfile(containerElement: HTMLElement, userProfile: { name: string; bio: string }) {
+  containerElement.replaceChildren();
+
+  const heading = document.createElement('h3');
+  heading.textContent = userProfile.name;
+
+  const bioPara = document.createElement('div');
+  bioPara.innerHTML = DOMPurify.sanitize(userProfile.bio, {
+    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
+    ALLOWED_ATTR: ['href', 'target', 'rel']
+  });
+
+  containerElement.append(heading, bioPara);
 }`,
     fileMatchPatterns: ['\\.innerHTML\\s*=', 'dangerouslySetInnerHTML'],
     defaultTargetFileName: 'src/views/profileView.ts',
     tags: ['xss', 'dompurify', 'innerhtml', 'dom', 'cwe-79']
   },

  // 8. Authentication: Insecure JWT (None algorithm / weak secret) -> Modern Asymmetric Ed25519 / RS256 with jose
  {
    id: 'auth-jwt-none-to-jose-asymmetric',
    title: 'Migração de JWT Inseguro (HS256 com segredo fraco / alg:none) para jose (EdDSA / RS256)',
    category: 'AUTHENTICATION',
    severity: 'CRITICAL',
    cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
    cweUrl: 'https://cwe.mitre.org/data/definitions/347.html',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    owaspUrl: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
    cvssReduction: { before: 9.8, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'jwt.verify(token, secret, { algorithms: ["HS256", "none"] })',
    modernReplacement: 'jose (jwtVerify com chave assimétrica pública / expiração obrigatória)',
    shortSummary: 'Tokens assinados com algoritmo simétrico fraco ou aceitando "none" permitem forjamento de identidade de superadmin. Use criptografia de chave pública assimétrica.',
    vulnerabilityExplanation: 'O ecossistema JWT antigo sofre de falhas graves como confusão de algoritmo (alg: none), onde um atacante remove a assinatura e o servidor aceita o token sem validar, além de segredos simétricos fracos que podem ser quebrados via Hashcat.',
    modernSolutionExplanation: 'A biblioteca moderna jose utiliza chaves assimétricas (Ed25519 ou RS256) onde o serviço de autenticação assina com chave privada e as APIs validam apenas com a chave pública, eliminando o risco de vazamento do segredo mestre.',
    prerequisites: [
      'npm install jose'
    ],
    beforeCode: `// ❌ INSEGURO: Aceita algoritmo 'none' e usa segredo simétrico estático fraco
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'segredo_fraco_123';

function verifyAuthToken(token) {
  // Vulnerável ao ataque alg: none e confusão de tipo de chave
  return jwt.verify(token, JWT_SECRET, {
    algorithms: ['HS256', 'none']
  });
}`,
    afterCode: `// ✅ SEGURO: Assinatura assimétrica Ed25519 com verificação estrita via 'jose'
import { jwtVerify, importSPKI } from 'jose';

// Chave pública carregada de forma segura (sem expor chave privada aos verificadores)
const PUBLIC_KEY_PEM = process.env.AUTH_PUBLIC_KEY_PEM!;

export async function verifyAuthToken(token: string) {
  const publicKey = await importSPKI(PUBLIC_KEY_PEM, 'Ed25519');

  const { payload } = await jwtVerify(token, publicKey, {
    issuer: 'https://auth.empresa.com.br',
    audience: 'https://api.empresa.com.br',
    algorithms: ['EdDSA'], // Apenas Ed25519 permitido explicitamente
    clockTolerance: 5       // 5 segundos de tolerância para skew de relógio
  });

  return payload;
}`,
    unifiedDiff: `--- src/middleware/authMiddleware.js (Legacy JWT)
+++ src/middleware/authMiddleware.ts (Modern jose EdDSA)
@@ -1,9 +1,18 @@
-// ❌ INSEGURO: Aceita algoritmo 'none' e usa segredo simétrico estático fraco
-const jwt = require('jsonwebtoken');
-const JWT_SECRET = 'segredo_fraco_123';
+// ✅ SEGURO: Assinatura assimétrica Ed25519 com verificação estrita via 'jose'
+import { jwtVerify, importSPKI } from 'jose';
 
-function verifyAuthToken(token) {
-  return jwt.verify(token, JWT_SECRET, {
-    algorithms: ['HS256', 'none']
+const PUBLIC_KEY_PEM = process.env.AUTH_PUBLIC_KEY_PEM!;
+
+export async function verifyAuthToken(token: string) {
+  const publicKey = await importSPKI(PUBLIC_KEY_PEM, 'Ed25519');
+
+  const { payload } = await jwtVerify(token, publicKey, {
+    issuer: 'https://auth.empresa.com.br',
+    audience: 'https://api.empresa.com.br',
+    algorithms: ['EdDSA'],
+    clockTolerance: 5
   });
+
+  return payload;
 }`,
     fileMatchPatterns: ['algorithms:.*none', 'jwt\\.verify\\(.*HS256'],
     defaultTargetFileName: 'src/middleware/authMiddleware.ts',
     tags: ['auth', 'jwt', 'jose', 'eddsa', 'cwe-347']
   },

  // 9. SSRF (Server-Side Request Forgery) -> Whitelist & Private IP Blocking
  {
    id: 'network-ssrf-to-safe-fetch',
    title: 'Prevenção de SSRF: Validação de DNS, Protocolo e Bloqueio de Redes Privadas',
    category: 'NETWORK_SSRF',
    severity: 'HIGH',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
    cweUrl: 'https://cwe.mitre.org/data/definitions/918.html',
    owasp: 'A10:2021 - Server-Side Request Forgery (SSRF)',
    owaspUrl: 'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/',
    cvssReduction: { before: 8.6, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'fetch(userSuppliedUrl) / axios.get(req.query.url)',
    modernReplacement: 'Safe HTTP Client com resolução DNS prévia e bloqueio de CIDR interno',
    shortSummary: 'Requisições HTTP iniciadas pelo servidor para URLs fornecidas por usuários podem acessar a rede interna (169.254.169.254, localhost, pods K8s).',
    vulnerabilityExplanation: 'Se a URL não for validada rigorosamente antes da chamada de rede, atacantes podem fornecer endereços como http://169.254.169.254/latest/meta-data/ para roubar credenciais temporárias da AWS ou invadir serviços administrativos internos inacessíveis pela internet.',
    modernSolutionExplanation: 'Valide o esquema (apenas https:), resolva o IP através de DNS antes de conectar e verifique se o endereço não pertence a blocos RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) ou link-local/cloud metadata.',
    prerequisites: [
      'Node.js nativo (node:dns, node:net, node:url)'
    ],
    beforeCode: `// ❌ INSEGURO: Requisição para URL fornecida pelo cliente sem validação (SSRF)
const axios = require('axios');

async function fetchWebhookPreview(webhookUrl) {
  // Um atacante pode enviar: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  const response = await axios.get(webhookUrl);
  return response.data;
}`,
    afterCode: `// ✅ SEGURO: Validação rigorosa de protocolo e bloqueio de IPs privados e Cloud Metadata
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const FORBIDDEN_CIDR_PATTERNS = [
  /^127\\./,           // Localhost
  /^10\\./,            // RFC 1918 Classe A
  /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./, // RFC 1918 Classe B
  /^192\\.168\\./,     // RFC 1918 Classe C
  /^169\\.254\\./,     // Link-Local / Cloud Metadata AWS/GCP
  /^0\\./,             // Endereços nulos
  /^::1$/,            // IPv6 Loopback
  /^fc00:/i,          // IPv6 ULA
  /^fe80:/i           // IPv6 Link-Local
];

export async function safeFetchWebhook(targetUrl: string): Promise<string> {
  const parsed = new URL(targetUrl);
  
  // 1. Apenas HTTPS estrito
  if (parsed.protocol !== 'https:') {
    throw new Error('SSRF Guard: Apenas protocolo HTTPS é permitido');
  }

  // 2. Resolução de DNS preventiva para checar IP de destino
  const dnsResult = await lookup(parsed.hostname);
  const resolvedIp = dnsResult.address;

  // 3. Bloqueio de IP privado / Cloud Metadata
  for (const pattern of FORBIDDEN_CIDR_PATTERNS) {
    if (pattern.test(resolvedIp)) {
      throw new Error(\`SSRF Guard: Conexão bloqueada para rede interna (\${resolvedIp})\`);
    }
  }

  // 4. Executa requisição com timeout curto e limite de payload
  const response = await fetch(parsed.toString(), {
    signal: AbortSignal.timeout(5000),
    headers: { 'User-Agent': 'SecScan-WebhookValidator/2.0' }
  });

  return await response.text();
}`,
    unifiedDiff: `--- src/services/webhookService.js (Legacy fetch)
+++ src/services/webhookService.ts (Modern SSRF Protected)
@@ -1,7 +1,38 @@
-// ❌ INSEGURO: Requisição para URL fornecida pelo cliente sem validação (SSRF)
-const axios = require('axios');
+// ✅ SEGURO: Validação rigorosa de protocolo e bloqueio de IPs privados e Cloud Metadata
+import { lookup } from 'node:dns/promises';
+
+const FORBIDDEN_CIDR_PATTERNS = [
+  /^127\\./,           // Localhost
+  /^10\\./,            // RFC 1918
+  /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./,
+  /^192\\.168\\./,
+  /^169\\.254\\./,     // Cloud Metadata
+  /^::1$/,
+];
+
+export async function safeFetchWebhook(targetUrl: string): Promise<string> {
+  const parsed = new URL(targetUrl);
+  
+  if (parsed.protocol !== 'https:') {
+    throw new Error('Apenas HTTPS é permitido');
+  }
 
-async function fetchWebhookPreview(webhookUrl) {
-  const response = await axios.get(webhookUrl);
-  return response.data;
+  const dnsResult = await lookup(parsed.hostname);
+  const resolvedIp = dnsResult.address;
+
+  for (const pattern of FORBIDDEN_CIDR_PATTERNS) {
+    if (pattern.test(resolvedIp)) {
+      throw new Error('Conexão bloqueada para rede interna');
+    }
+  }
+
+  const response = await fetch(parsed.toString(), {
+    signal: AbortSignal.timeout(5000)
+  });
+
+  return await response.text();
 }`,
     fileMatchPatterns: ['axios\\.get\\(.*req\\.', 'fetch\\(.*req\\.'],
     defaultTargetFileName: 'src/services/webhookService.ts',
     tags: ['ssrf', 'network', 'fetch', 'dns', 'cwe-918']
   },

  // 10. Path Traversal & Unsafe File Access -> Path Normalization & Root Directory Sandboxing
  {
    id: 'filesystem-path-traversal-to-sandboxed',
    title: 'Prevenção de Path Traversal (CWE-22) via Sandboxing e Normalização de Caminho',
    category: 'FILE_SYSTEM',
    severity: 'HIGH',
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    cweUrl: 'https://cwe.mitre.org/data/definitions/22.html',
    owasp: 'A01:2021 - Broken Access Control',
    owaspUrl: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    cvssReduction: { before: 8.5, after: 0.0 },
    language: 'typescript',
    legacyLibraryOrPattern: 'fs.readFileSync(path.join(UPLOAD_DIR, req.query.filename))',
    modernReplacement: 'path.resolve + verificação estrita de prefixo de sandbox raiz',
    shortSummary: 'Concatenação com path.join permite sequências de escape "../../etc/passwd". Valide com path.resolve e certifique-se de que o caminho permaneça dentro do diretório seguro.',
    vulnerabilityExplanation: 'O método path.join() resolve caminhos relativos de forma flexível. Quando um invasor envia ../../../, o arquivo resultante pode apontar para chaves SSH, arquivos de configuração do sistema ou banco de dados.',
    modernSolutionExplanation: 'Utilize path.resolve() para obter o caminho canônico absoluto e certifique-se de que ele começa com o caminho absoluto do diretório sandbox seguro com separador de diretório, além de rejeitar caracteres nulos (\\0).',
    prerequisites: [
      'Node.js nativo (node:path, node:fs/promises)'
    ],
    beforeCode: `// ❌ INSEGURO: Concatenação de caminho vulnerável a ../../ (Path Traversal)
const fs = require('fs');
const path = require('path');
const UPLOADS_DIR = '/var/app/uploads';

function getUploadedFile(userFilename) {
  // Se userFilename for '../../../../etc/passwd', lerá arquivos confidenciais
  const targetPath = path.join(UPLOADS_DIR, userFilename);
  return fs.readFileSync(targetPath, 'utf8');
}`,
    afterCode: `// ✅ SEGURO: Resolução canônica de caminho com verificação estrita de sandbox
import { readFile } from 'node:fs/promises';
import { resolve, normalize } from 'node:path';

const UPLOADS_DIR = resolve('/var/app/uploads');

export async function getUploadedFileSafe(userFilename: string): Promise<string> {
  // 1. Rejeita null-byte poisoning
  if (userFilename.includes('\\0')) {
    throw new Error('Path Traversal Guard: Caractere nulo detectado');
  }

  // 2. Resolve o caminho canônico absoluto
  const safeNormalizedPath = resolve(UPLOADS_DIR, normalize(userFilename));

  // 3. Garante que o caminho canônico comece rigorosamente com o diretório raiz
  const isWithinSandbox = safeNormalizedPath.startsWith(UPLOADS_DIR + '/');
  if (!isWithinSandbox && safeNormalizedPath !== UPLOADS_DIR) {
    throw new Error('Path Traversal Guard: Tentativa de escape do diretório base bloqueada');
  }

  return await readFile(safeNormalizedPath, 'utf8');
}`,
    unifiedDiff: `--- src/controllers/fileController.js (Legacy path.join)
+++ src/controllers/fileController.ts (Modern Sandboxed Path)
@@ -1,8 +1,21 @@
-// ❌ INSEGURO: Concatenação de caminho vulnerável a ../../ (Path Traversal)
-const fs = require('fs');
-const path = require('path');
-const UPLOADS_DIR = '/var/app/uploads';
+// ✅ SEGURO: Resolução canônica de caminho com verificação estrita de sandbox
+import { readFile } from 'node:fs/promises';
+import { resolve, normalize } from 'node:path';
 
-function getUploadedFile(userFilename) {
-  const targetPath = path.join(UPLOADS_DIR, userFilename);
-  return fs.readFileSync(targetPath, 'utf8');
+const UPLOADS_DIR = resolve('/var/app/uploads');
+
+export async function getUploadedFileSafe(userFilename: string): Promise<string> {
+  if (userFilename.includes('\\0')) {
+    throw new Error('Caractere nulo detectado');
+  }
+
+  const safeNormalizedPath = resolve(UPLOADS_DIR, normalize(userFilename));
+
+  const isWithinSandbox = safeNormalizedPath.startsWith(UPLOADS_DIR + '/');
+  if (!isWithinSandbox && safeNormalizedPath !== UPLOADS_DIR) {
+    throw new Error('Tentativa de escape do diretório base bloqueada');
+  }
+
+  return await readFile(safeNormalizedPath, 'utf8');
 }`,
     fileMatchPatterns: ['path\\.join\\(.*req\\.', 'fs\\.readFileSync\\(.*path\\.join'],
     defaultTargetFileName: 'src/controllers/fileController.ts',
     tags: ['filesystem', 'path-traversal', 'sandbox', 'cwe-22']
   }
 ];

/**
  * Find applicable refactoring recipes for a specific file or finding
  */
export function findApplicableRecipes(
  files: ScannedFile[],
  findings: ScanFinding[]
): { recipe: SecurityRefactoringRecipe; matchedFile?: ScannedFile; matchedFinding?: ScanFinding }[] {
  const results: { recipe: SecurityRefactoringRecipe; matchedFile?: ScannedFile; matchedFinding?: ScanFinding }[] = [];

  for (const recipe of REFACTORING_RECIPES) {
    let matchedFile: ScannedFile | undefined;
    let matchedFinding: ScanFinding | undefined;

    // 1. Try finding match by finding rule or category
    matchedFinding = findings.find(f => {
      const rule = (f.ruleId || '').toLowerCase();
      const name = (f.ruleName || '').toLowerCase();
      const cat = (f.category || '').toLowerCase();

      if (recipe.category === 'CRYPTOGRAPHY' && (rule.includes('crypto') || rule.includes('hash') || name.includes('crypto') || name.includes('hash'))) {
        return true;
      }
      if (recipe.category === 'SECRETS' && (cat.includes('credential') || cat.includes('key') || cat.includes('secret'))) {
        return true;
      }
      if (recipe.category === 'INJECTION' && (cat.includes('sql') || rule.includes('sql'))) {
        return true;
      }
      if (recipe.category === 'DATA_VALIDATION' && (rule.includes('innerhtml') || rule.includes('xss') || rule.includes('taint'))) {
        return true;
      }
      return false;
    });

    // 2. Try finding match in file contents
    if (recipe.fileMatchPatterns && recipe.fileMatchPatterns.length > 0) {
      for (const pattern of recipe.fileMatchPatterns) {
        const regex = new RegExp(pattern, 'i');
        const found = files.find(f => f.content && regex.test(f.content));
        if (found) {
          matchedFile = found;
          break;
        }
      }
    }

    // Default match to a file if finding exists
    if (!matchedFile && matchedFinding) {
      matchedFile = files.find(f => f.path === matchedFinding?.file || f.name === matchedFinding?.file);
    }

    results.push({
      recipe,
      matchedFile,
      matchedFinding
    });
  }

  return results;
}

/**
  * Generates a line-by-line diff model for rich side-by-side or unified rendering
  */
export interface DiffLine {
  type: 'unchanged' | 'removed' | 'added';
  lineNumberBefore?: number;
  lineNumberAfter?: number;
  content: string;
}

export function parseUnifiedDiffLines(before: string, after: string): {
  beforeLines: { lineNumber: number; content: string; isModified: boolean }[];
  afterLines: { lineNumber: number; content: string; isModified: boolean }[];
  unifiedLines: DiffLine[];
} {
  const beforeSplit = before.split('\n');
  const afterSplit = after.split('\n');

  const beforeLines = beforeSplit.map((content, idx) => ({
    lineNumber: idx + 1,
    content,
    isModified: true
  }));

  const afterLines = afterSplit.map((content, idx) => ({
    lineNumber: idx + 1,
    content,
    isModified: true
  }));

  const unifiedLines: DiffLine[] = [];

  // Add removed lines
  beforeSplit.forEach((l, idx) => {
    unifiedLines.push({
      type: 'removed',
      lineNumberBefore: idx + 1,
      content: l
    });
  });

  // Add added lines
  afterSplit.forEach((l, idx) => {
    unifiedLines.push({
      type: 'added',
      lineNumberAfter: idx + 1,
      content: l
    });
  });

  return { beforeLines, afterLines, unifiedLines };
}
