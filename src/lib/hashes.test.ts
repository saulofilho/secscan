import { createHash, createHmac, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { hmacSha256, md5, sha1, sha256, toHex, utf8Bytes } from './hashes';

const samples: Uint8Array[] = [
  new Uint8Array(0),
  utf8Bytes('abc'),
  utf8Bytes('The quick brown fox jumps over the lazy dog'),
  utf8Bytes('ação — ünïcödé ✓'),
  ...[55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4097].map((size) => new Uint8Array(randomBytes(size)))
];

describe('hashes', () => {
  it('md5, sha1 e sha256 batem com node:crypto', () => {
    for (const sample of samples) {
      expect(toHex(md5(sample))).toBe(createHash('md5').update(sample).digest('hex'));
      expect(toHex(sha1(sample))).toBe(createHash('sha1').update(sample).digest('hex'));
      expect(toHex(sha256(sample))).toBe(createHash('sha256').update(sample).digest('hex'));
    }
  });

  it('hmacSha256 bate com node:crypto, inclusive com chave maior que o bloco', () => {
    for (const keySize of [0, 1, 32, 64, 65, 200]) {
      const key = new Uint8Array(randomBytes(keySize));
      for (const sample of samples) {
        expect(toHex(hmacSha256(key, sample))).toBe(createHmac('sha256', key).update(sample).digest('hex'));
      }
    }
  });
});
