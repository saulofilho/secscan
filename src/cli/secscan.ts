#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { DEFAULT_RULES } from '../lib/defaultRules';

function calculateEntropy(str: string): number {
  if (!str) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i += 1) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char of Object.keys(frequencies)) {
    const p = frequencies[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function maskSecret(secret: string): string {
  const clean = secret.trim().replace(/^['"]|['"]$/g, '');
  if (clean.length <= 8) return '••••••••';
  return `${clean.slice(0, 4)}••••••••${clean.slice(-4)}`;
}

function shouldIgnore(filePath: string, customIgnores: string[] = []): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const ignorePatterns = [
    '/node_modules/', 'node_modules/',
    '/vendor/', 'vendor/',
    '/.git/', '.git/',
    '/dist/', 'dist/',
    '/build/', 'build/',
    '.min.js', '.bundle.js',
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  ];

  return [...ignorePatterns, ...customIgnores].some((pattern) => normalized.includes(pattern));
}

function getFiles(dir: string, customIgnores: string[] = [], fileList: string[] = []): string[] {
  if (!fs.existsSync(dir)) return fileList;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (shouldIgnore(fullPath, customIgnores)) continue;
    if (entry.isDirectory()) {
      getFiles(fullPath, customIgnores, fileList);
    } else if (/\.(js|jsx|ts|tsx|mjs|cjs|json|env|yaml|yml)$/i.test(entry.name)) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

interface CliFinding {
  id: string;
  ruleId: string;
  ruleName: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  matchedSecret: string;
  maskedSecret: string;
  entropy: number;
  snippet: string;
  description: string;
}

function run(): void {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
SecScan CLI

Usage:
  secscan [target_directory] [options]

Options:
  --format <table|json|sarif|csv>   Output format (Default: table)
  --rules <file.json>               Extra regex rules JSON file
  --ignore <glob>                   Additional ignore patterns (comma-separated)
  --fail-on <critical|high|medium>  Exit 1 when a finding meets the severity
  --max-risk <score>                Exit 1 when the risk score exceeds the threshold
  --output <file>                   Write the report to a file
  --help                            Show this help message
`);
    process.exit(0);
  }

  const targetDir = args[0] && !args[0].startsWith('--') ? args[0] : '.';
  const formatIdx = args.indexOf('--format');
  const format = formatIdx !== -1 && args[formatIdx + 1] ? args[formatIdx + 1] : 'table';
  const outIdx = args.indexOf('--output');
  const outputFile = outIdx !== -1 && args[outIdx + 1] ? args[outIdx + 1] : null;
  const ignoreIdx = args.indexOf('--ignore');
  const customIgnores = ignoreIdx !== -1 && args[ignoreIdx + 1] ? args[ignoreIdx + 1].split(',') : [];
  const failOnIdx = args.indexOf('--fail-on');
  const failOn = failOnIdx !== -1 && args[failOnIdx + 1] ? args[failOnIdx + 1].toUpperCase() : null;
  const maxRiskIdx = args.indexOf('--max-risk') !== -1 ? args.indexOf('--max-risk') : args.indexOf('--max-risk-score');
  const maxRisk = maxRiskIdx !== -1 && args[maxRiskIdx + 1] ? parseFloat(args[maxRiskIdx + 1]) : null;

  let rules = DEFAULT_RULES.filter((rule) => rule.enabled !== false);
  const rulesIdx = args.indexOf('--rules');
  if (rulesIdx !== -1 && args[rulesIdx + 1]) {
    try {
      const parsedRules = JSON.parse(fs.readFileSync(args[rulesIdx + 1], 'utf-8'));
      rules = [...rules, ...parsedRules];
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('[SecScan Error] Failed to read rules file:', message);
    }
  }

  const startTime = Date.now();
  const files = getFiles(path.resolve(targetDir), customIgnores);
  const findings: CliFinding[] = [];

  for (const file of files) {
    let content = '';
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    for (const rule of rules) {
      const regex = new RegExp(rule.pattern, rule.flags || 'g');
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const full = match[0];
        const entropy = calculateEntropy(full);
        if (rule.minEntropy && entropy < rule.minEntropy) continue;

        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: `sec-${findings.length + 1}`,
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          severity: rule.severity,
          file: path.relative(process.cwd(), file),
          line: lineNum,
          matchedSecret: full,
          maskedSecret: maskSecret(full),
          entropy,
          snippet: (lines[lineNum - 1] || '').trim(),
          description: rule.description,
        });
      }
    }
  }

  const criticalCount = findings.filter((finding) => finding.severity === 'CRITICAL').length;
  const highCount = findings.filter((finding) => finding.severity === 'HIGH').length;
  const mediumCount = findings.filter((finding) => finding.severity === 'MEDIUM').length;
  const lowCount = findings.filter((finding) => finding.severity === 'LOW').length;
  const infoCount = findings.filter((finding) => finding.severity === 'INFO').length;
  const rawRiskPoints = (criticalCount * 25) + (highCount * 15) + (mediumCount * 6) + (lowCount * 2) + (infoCount * 0.5);
  const riskScore = findings.length === 0
    ? 0
    : Math.min(100, Math.max(1, Math.round(100 * (1 - Math.exp(-rawRiskPoints / 50)))));

  let riskLevel = 'MINIMAL';
  if (riskScore >= 75) riskLevel = 'CRITICAL';
  else if (riskScore >= 50) riskLevel = 'HIGH';
  else if (riskScore >= 25) riskLevel = 'MEDIUM';
  else if (riskScore > 0) riskLevel = 'LOW';

  const report = {
    scanner: 'SecScan AppSec Suite',
    version: '0.1.0',
    rulesSource: 'src/lib/defaultRules.ts',
    timestamp: new Date().toISOString(),
    targetDirectory: targetDir,
    totalFilesScanned: files.length,
    totalFindings: findings.length,
    metrics: {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      riskScore,
      riskLevel,
      rawRiskPoints: Number(rawRiskPoints.toFixed(1)),
    },
    findings,
    durationMs: Date.now() - startTime,
  };

  let formattedOutput = '';
  if (format === 'json') {
    formattedOutput = JSON.stringify(report, null, 2);
  } else if (format === 'csv') {
    const header = 'ID,Severity,Rule,File,Line,Entropy,MaskedSecret\n';
    const rows = findings.map((finding) =>
      `${finding.id},${finding.severity},"${finding.ruleName}","${finding.file}",${finding.line},${finding.entropy},"${finding.maskedSecret}"`
    ).join('\n');
    formattedOutput = header + rows;
  } else if (format === 'sarif') {
    formattedOutput = JSON.stringify({
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'SecScan AppSec Suite', semanticVersion: '0.1.0' } },
        properties: { riskScore, riskLevel, rawRiskPoints, criticalCount, highCount, mediumCount, lowCount },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? 'error' : 'warning',
          message: { text: `[${finding.ruleName}] ${finding.description}` },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: finding.file },
              region: { startLine: finding.line },
            },
          }],
        })),
      }],
    }, null, 2);
  } else {
    const divider = '─'.repeat(80);
    console.log('\nSecScan — relatório estático');
    console.log(divider);
    console.log(`Alvo: ${targetDir} | Arquivos: ${files.length} | Achados: ${findings.length} | ${report.durationMs}ms`);
    console.log(`Risk score: ${riskScore}/100 (${riskLevel}) | Regras: src/lib/defaultRules.ts`);
    console.log(divider);
    for (const finding of findings) {
      console.log(`${finding.severity.padEnd(8)} ${finding.ruleName}  ${finding.file}:${finding.line}`);
      console.log(`         ${finding.maskedSecret}`);
    }
    if (findings.length === 0) console.log('Nenhum achado.');
  }

  if (formattedOutput) {
    if (outputFile) fs.writeFileSync(outputFile, formattedOutput);
    else console.log(formattedOutput);
  } else if (outputFile) {
    fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));
  }

  if (maxRisk !== null && !Number.isNaN(maxRisk) && riskScore > maxRisk) {
    console.error(`\n[SecScan Quality Gate] Risk score ${riskScore}/100 passou do teto ${maxRisk}.`);
    process.exit(1);
  }

  if (failOn) {
    const levels = ['MEDIUM', 'HIGH', 'CRITICAL'];
    const thresholdIdx = levels.indexOf(failOn);
    const hasFailingIssue = findings.some((finding) => levels.indexOf(finding.severity) >= thresholdIdx);
    if (hasFailingIssue) {
      console.error(`\n[SecScan CI Failure] Achado em ou acima de ${failOn}.`);
      process.exit(1);
    }
  }
}

run();
