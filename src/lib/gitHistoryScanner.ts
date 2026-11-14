/**
 * Finds secrets in the lines added by each commit of a `git log -p` output.
 * Pure parsing: the caller runs git and tells which secrets are still in HEAD.
 */
import { RegexRule } from '../types';
import { DEFAULT_RULES } from './defaultRules';
import { calculateShannonEntropy, maskEntropyToken } from './entropyScanner';

export interface GitCommitSecretLeak {
  commitHash: string;
  author: string;
  date: string;
  commitMessage: string;
  file: string;
  ruleName: string;
  /** Always masked. The raw secret never leaves the server. */
  maskedSecret: string;
  statusInHead: 'DELETED_FROM_HEAD_BUT_LEAKED_IN_GIT_HISTORY' | 'STILL_IN_SOURCE';
  dangerLevel: 'CRITICAL' | 'HIGH';
  gitRemediationCommand: string;
}

export interface GitHistoryScanResult {
  isGitRepository: boolean;
  repoRoot: string;
  commitsScanned: number;
  /** True when the history has more commits than the scan limit. */
  truncated: boolean;
  leaks: GitCommitSecretLeak[];
}

/** Record separators used in the --format string. They cannot appear in a commit subject. */
export const GIT_LOG_COMMIT_MARK = '\u0001';
export const GIT_LOG_FIELD_MARK = '\u0002';
export const GIT_LOG_FORMAT = `--format=${GIT_LOG_COMMIT_MARK}%H${GIT_LOG_FIELD_MARK}%an <%ae>${GIT_LOG_FIELD_MARK}%aI${GIT_LOG_FIELD_MARK}%s`;

const SECRET_CATEGORIES = new Set(['CLOUD_CREDENTIAL', 'API_KEY', 'AUTH_TOKEN', 'DATABASE_URI', 'PRIVATE_KEY', 'PASSWORD', 'CUSTOM_REGEX']);
const MAX_LINE_LENGTH = 2000;

interface CompiledRule {
  rule: RegexRule;
  regex: RegExp;
}

function compileRules(rules: RegexRule[]): CompiledRule[] {
  const compiled: CompiledRule[] = [];
  for (const rule of rules) {
    if (!rule.enabled || !SECRET_CATEGORIES.has(rule.category)) continue;
    let pattern = rule.pattern;
    let flags = rule.flags || 'g';
    if (pattern.startsWith('(?i)')) {
      pattern = pattern.slice(4);
      if (!flags.includes('i')) flags += 'i';
    }
    if (!flags.includes('g')) flags += 'g';
    try {
      compiled.push({ rule, regex: new RegExp(pattern, flags) });
    } catch {
      // An invalid custom rule is skipped, as in the workspace scan.
    }
  }
  return compiled;
}

export interface RawGitLeak extends Omit<GitCommitSecretLeak, 'statusInHead' | 'gitRemediationCommand'> {
  /** Raw match. Used by the server to check HEAD, then dropped. */
  secret: string;
}

/**
 * Parses `git log -p --unified=0 <GIT_LOG_FORMAT>` output. One leak per
 * distinct secret and file, attributed to the oldest commit that added it.
 */
export function scanGitLogPatch(log: string, rules: RegexRule[] = DEFAULT_RULES): { commitsScanned: number; leaks: RawGitLeak[] } {
  const compiled = compileRules(rules);
  const byKey = new Map<string, RawGitLeak>();
  let commitsScanned = 0;

  for (const block of log.split(GIT_LOG_COMMIT_MARK)) {
    if (!block.trim()) continue;
    const newline = block.indexOf('\n');
    const header = newline === -1 ? block : block.slice(0, newline);
    const [commitHash, author, date, ...subject] = header.split(GIT_LOG_FIELD_MARK);
    if (!commitHash || !/^[0-9a-f]{7,64}$/.test(commitHash)) continue;
    commitsScanned += 1;
    if (newline === -1) continue;

    let file = '';
    for (const line of block.slice(newline + 1).split('\n')) {
      if (line.startsWith('+++ ')) {
        const target = line.slice(4).trim();
        file = target === '/dev/null' ? '' : target.replace(/^b\//, '');
        continue;
      }
      if (!file || !line.startsWith('+') || line.length > MAX_LINE_LENGTH) continue;
      const added = line.slice(1);
      for (const { rule, regex } of compiled) {
        regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = regex.exec(added)) !== null) {
          const secret = match[0];
          if (!secret) break;
          if (rule.minEntropy && calculateShannonEntropy(secret) < rule.minEntropy) continue;
          // git log lists newest first, so a later write is the older commit.
          byKey.set(`${file}\u0000${secret}`, {
            commitHash: commitHash.slice(0, 12),
            author: author || '',
            date: date || '',
            commitMessage: subject.join(GIT_LOG_FIELD_MARK),
            file,
            ruleName: rule.name,
            secret,
            maskedSecret: maskEntropyToken(secret),
            dangerLevel: rule.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH'
          });
        }
      }
    }
  }

  return { commitsScanned, leaks: [...byKey.values()] };
}

export function finalizeGitLeak(raw: RawGitLeak, stillInHead: boolean): GitCommitSecretLeak {
  const { secret: _secret, ...rest } = raw;
  return {
    ...rest,
    statusInHead: stillInHead ? 'STILL_IN_SOURCE' : 'DELETED_FROM_HEAD_BUT_LEAKED_IN_GIT_HISTORY',
    gitRemediationCommand: stillInHead
      ? `# 1) Revogue e rotacione a credencial. 2) Remova de ${raw.file} e faça commit. 3) Reescreva o histórico:\ngit filter-repo --replace-text replacements.txt   # replacements.txt: <segredo>==>***REMOVED***`
      : '# 1) Revogue e rotacione a credencial: ela continua legível em qualquer clone. 2) Reescreva o histórico:\ngit filter-repo --replace-text replacements.txt   # replacements.txt: <segredo>==>***REMOVED***\ngit push --force --all && git push --force --tags'
  };
}
