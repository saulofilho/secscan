import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  finalizeGitLeak,
  GIT_LOG_FORMAT,
  GitHistoryScanResult,
  scanGitLogPatch,
} from '../src/lib/gitHistoryScanner';

const run = promisify(execFile);
const MAX_OUTPUT_BYTES = 256 * 1024 * 1024;

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await run('git', args, { cwd, maxBuffer: MAX_OUTPUT_BYTES, timeout: 120000 });
  return stdout;
}

/**
 * Runs `git log -p` in `dir` and scans every added line with the default
 * secret rules. Read-only: it never writes to the repository.
 */
export async function collectGitHistoryLeaks(dir: string, maxCommits = 1000): Promise<GitHistoryScanResult> {
  const requested = path.resolve(dir);
  let repoRoot: string;
  try {
    repoRoot = (await git(requested, ['rev-parse', '--show-toplevel'])).trim();
  } catch {
    return { isGitRepository: false, repoRoot: requested, commitsScanned: 0, truncated: false, leaks: [] };
  }

  const limit = Math.max(1, Math.min(Math.floor(maxCommits) || 1000, 20000));
  let total = 0;
  try {
    total = Number((await git(repoRoot, ['rev-list', '--count', '--all'])).trim()) || 0;
  } catch {
    // A repository without commits: the log below comes back empty.
  }

  let log = '';
  try {
    log = await git(repoRoot, [
      'log', '--all', '-p', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0',
      `--max-count=${limit}`, GIT_LOG_FORMAT,
    ]);
  } catch (error) {
    if (total > 0) throw error;
  }

  const { commitsScanned, leaks } = scanGitLogPatch(log);
  const headCache = new Map<string, string | null>();
  const readHead = (file: string): string | null => {
    if (!headCache.has(file)) {
      const full = path.resolve(repoRoot, file);
      let content: string | null = null;
      if (full.startsWith(repoRoot + path.sep)) {
        try {
          content = fs.readFileSync(full, 'utf8');
        } catch {
          content = null;
        }
      }
      headCache.set(file, content);
    }
    return headCache.get(file) ?? null;
  };

  return {
    isGitRepository: true,
    repoRoot,
    commitsScanned,
    truncated: total > commitsScanned,
    leaks: leaks
      .map((raw) => finalizeGitLeak(raw, Boolean(readHead(raw.file)?.includes(raw.secret))))
      .sort((a, b) => (a.date < b.date ? 1 : -1)),
  };
}
