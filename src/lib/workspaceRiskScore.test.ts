import { describe, expect, it } from 'vitest';
import { calculateCumulativeWorkspaceRiskScore } from './scanner';

describe('quality gate', () => {
  it('zera o score quando não há achado', () => {
    const score = calculateCumulativeWorkspaceRiskScore({
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0
    });
    expect(score.riskScore).toBe(0);
    expect(score.rawPoints).toBe(0);
    expect(score.riskLevel).toBe('MINIMAL');
  });

  it('satura um crítico em round(100 * (1 - exp(-25/50)))', () => {
    const score = calculateCumulativeWorkspaceRiskScore({
      criticalCount: 1,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0
    });
    const expected = Math.min(100, Math.max(1, Math.round(100 * (1 - Math.exp(-25 / 50)))));
    expect(score.rawPoints).toBe(25);
    expect(score.riskScore).toBe(expected);
    expect(score.riskLevel).toBe('MEDIUM');
  });
});
