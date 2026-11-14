import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { auditJwtToken, findWeakHs256Secret, SAMPLE_TOKENS } from './jwtInspectorEngine';

function sign(payload: Record<string, unknown>, secret: string): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}`;
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`;
}

describe('JWT weak secret', () => {
  it('confirma o segredo quando o HMAC recalculado bate com a assinatura', () => {
    const token = sign({ sub: 'u1', exp: 4102444800 }, 'changeme');
    expect(findWeakHs256Secret(token)).toBe('changeme');
    const report = auditJwtToken(token);
    expect(report.isWeakSecretDetected).toBe(true);
    expect(report.guessedSecret).toBe('changeme');
  });

  it('não acusa segredo fraco quando a chave está fora do dicionário', () => {
    const token = sign({ sub: 'u1', exp: 4102444800 }, 'k9$Lq2!vX7#pR4@zT8&nW3^mB6*cF1(d');
    const report = auditJwtToken(token);
    expect(report.isWeakSecretDetected).toBe(false);
    expect(report.vulnerabilities.some((v) => v.id === 'jwt-weak-hmac-secret')).toBe(false);
  });

  it('aceita dicionário extra do usuário', () => {
    const token = sign({ sub: 'u1', exp: 4102444800 }, 'acme-internal-2024');
    expect(auditJwtToken(token).isWeakSecretDetected).toBe(false);
    expect(auditJwtToken(token, ['acme-internal-2024']).guessedSecret).toBe('acme-internal-2024');
  });

  it('a amostra HS256 é assinada de verdade com "secret"', () => {
    const sample = SAMPLE_TOKENS.find((item) => item.name.includes('HMAC'));
    expect(auditJwtToken(sample!.token).guessedSecret).toBe('secret');
  });
});
