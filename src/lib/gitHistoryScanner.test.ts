import { describe, expect, it } from 'vitest';
import { finalizeGitLeak, GIT_LOG_COMMIT_MARK as C, GIT_LOG_FIELD_MARK as F, scanGitLogPatch } from './gitHistoryScanner';

const token = `ghp_${'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'}`;
const log = [
  `${C}${'b'.repeat(40)}${F}Ana <ana@example.com>${F}2026-02-02T10:00:00Z${F}remove token`,
  '',
  'diff --git a/a.js b/a.js',
  '--- a/a.js',
  '+++ b/a.js',
  '@@ -1 +1 @@',
  `-const key = "${token}";`,
  '+const key = process.env.GH;',
  `${C}${'a'.repeat(40)}${F}Ana <ana@example.com>${F}2026-01-01T10:00:00Z${F}add config`,
  '',
  'diff --git a/a.js b/a.js',
  '--- /dev/null',
  '+++ b/a.js',
  '@@ -0,0 +1 @@',
  `+const key = "${token}";`,
].join('\n');

describe('git history scanner', () => {
  it('acha o segredo só na linha adicionada e atribui ao commit que o introduziu', () => {
    const { commitsScanned, leaks } = scanGitLogPatch(log);
    expect(commitsScanned).toBe(2);
    expect(leaks).toHaveLength(1);
    expect(leaks[0].commitHash).toBe('a'.repeat(12));
    expect(leaks[0].file).toBe('a.js');
    expect(leaks[0].commitMessage).toBe('add config');
  });

  it('não devolve o segredo em claro ao finalizar', () => {
    const { leaks } = scanGitLogPatch(log);
    const leak = finalizeGitLeak(leaks[0], false);
    expect(JSON.stringify(leak)).not.toContain(token);
    expect(leak.statusInHead).toBe('DELETED_FROM_HEAD_BUT_LEAKED_IN_GIT_HISTORY');
  });

  it('log vazio não gera achado', () => {
    expect(scanGitLogPatch('')).toEqual({ commitsScanned: 0, leaks: [] });
  });
});
