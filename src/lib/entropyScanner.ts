import { ScannedFile } from '../types';

export interface EntropyFinding {
  id: string;
  file: string;
  line: number;
  snippet: string;
  token: string;
  maskedToken: string;
  entropy: number;
  entropyLevel: 'EXTREME' | 'HIGH' | 'MEDIUM';
  charset: 'BASE64' | 'HEXADECIMAL' | 'ALPHANUMERIC' | 'ASCII';
  probableType: string;
  recommendation: string;
}

export interface EntropyScanReport {
  totalTokensScanned: number;
  highEntropyFindings: EntropyFinding[];
  averageFileEntropy: number;
  highestEntropyObserved: number;
  entropyDistribution: {
    low: number;      // < 3.2
    moderate: number; // 3.2 - 4.2
    high: number;     // 4.2 - 5.4
    extreme: number;  // > 5.4
  };
}

/**
 * Calculates Shannon Entropy of a string in bits per character.
 * Range is generally 0.0 (uniform string like "aaaaa") to ~6.0+ (random base64/crypto key).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Masks sensitive token for secure UI presentation
 */
export function maskEntropyToken(token: string): string {
  if (token.length <= 8) return '****';
  const prefix = token.slice(0, 4);
  const suffix = token.slice(-4);
  return `${prefix}${'*'.repeat(Math.min(token.length - 8, 16))}${suffix}`;
}

export function detectCharset(str: string): 'BASE64' | 'HEXADECIMAL' | 'ALPHANUMERIC' | 'ASCII' {
  if (/^[0-9a-fA-F]+$/.test(str)) return 'HEXADECIMAL';
  if (/^[a-zA-Z0-9+/=_-]+$/.test(str)) return 'BASE64';
  if (/^[a-zA-Z0-9]+$/.test(str)) return 'ALPHANUMERIC';
  return 'ASCII';
}

export function scanWorkspaceEntropy(
  files: ScannedFile[],
  entropyThreshold: number = 4.2
): EntropyScanReport {
  const findings: EntropyFinding[] = [];
  let totalTokensScanned = 0;
  let totalEntropySum = 0;
  let highestEntropyObserved = 0;

  const distribution = {
    low: 0,
    moderate: 0,
    high: 0,
    extreme: 0
  };

  // 1. Scan tokens in workspace files
  for (const file of files) {
    // Skip third-party libraries & node_modules
    if (file.path.includes('node_modules') || file.path.includes('dist/assets')) continue;

    const lines = file.content.split('\n');
    lines.forEach((line, lineIdx) => {
      // Find candidate string tokens surrounded by quotes or whitespace
      const tokenMatches = line.matchAll(/["']([A-Za-z0-9+/=_\-]{16,128})["']/g);

      for (const match of tokenMatches) {
        const candidate = match[1];
        // Exclude common programming terms or path words
        if (candidate.includes(' ') || candidate.toLowerCase().includes('react') || candidate.toLowerCase().includes('component')) continue;

        totalTokensScanned++;
        const entropy = calculateShannonEntropy(candidate);
        totalEntropySum += entropy;
        if (entropy > highestEntropyObserved) highestEntropyObserved = entropy;

        if (entropy < 3.2) distribution.low++;
        else if (entropy < 4.2) distribution.moderate++;
        else if (entropy < 5.4) distribution.high++;
        else distribution.extreme++;

        if (entropy >= entropyThreshold) {
          const charset = detectCharset(candidate);
          let probableType = 'Segredo Aleatório de Alta Entropia';
          if (candidate.startsWith('eyJ')) probableType = 'JWT Token Estruturado';
          else if (candidate.length === 32 || candidate.length === 64) probableType = 'Chave Criptográfica / Hash Privado';
          else if (charset === 'HEXADECIMAL') probableType = 'Chave Hexadecimal Aleatória';
          else if (charset === 'BASE64') probableType = 'Token Base64 de Autenticação';

          findings.push({
            id: `entropy-${file.path}-${lineIdx}-${match.index}`,
            file: file.path,
            line: lineIdx + 1,
            snippet: line.trim(),
            token: candidate,
            maskedToken: maskEntropyToken(candidate),
            entropy,
            entropyLevel: entropy >= 5.4 ? 'EXTREME' : 'HIGH',
            charset,
            probableType,
            recommendation: 'Extraia este valor para o cofre de segredos (HashiCorp Vault / AWS Secrets Manager) ou variáveis de ambiente .env.'
          });
        }
      }
    });
  }

  const averageFileEntropy = totalTokensScanned > 0 ? Number((totalEntropySum / totalTokensScanned).toFixed(2)) : 0;

  return {
    totalTokensScanned,
    highEntropyFindings: findings.sort((a, b) => b.entropy - a.entropy),
    averageFileEntropy,
    highestEntropyObserved,
    entropyDistribution: distribution
  };
}
