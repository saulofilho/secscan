#!/usr/bin/env node

/**
 * SecScan CLI - Automated Secret & API Path Static Analysis Tool
 * Usage:
 *   node bin/secscan.js [directory] [options]
 * Options:
 *   --format <json|table|sarif|csv>   Output format (default: table)
 *   --rules <path>                    Custom regex rules JSON file
 *   --ignore <pattern>                Additional directories/patterns to ignore
 *   --fail-on <critical|high|medium>  Exit code 1 if findings meet/exceed severity
 *   --output <path>                   Write report directly to file
 *   --help                            Display command line manual
 */

import fs from 'fs';
import path from 'path';

// Built-in Default Detection Rules
const DEFAULT_RULES = [
  {
    id: 'sec-aws-akid',
    name: 'AWS Access Key ID',
    pattern: '\\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\\b',
    flags: 'g',
    severity: 'CRITICAL',
    category: 'CLOUD_CREDENTIAL',
    description: 'AWS Access Key ID hardcoded in repository',
    minEntropy: 3.5
  },
  {
    id: 'sec-aws-secret',
    name: 'AWS Secret Access Key',
    pattern: '(?:aws_secret_access_key|aws_secret|aws_key)\\s*[:=]\\s*[\'"][A-Za-z0-9/+=]{40}[\'"]',
    flags: 'gi',
    severity: 'CRITICAL',
    category: 'CLOUD_CREDENTIAL',
    description: 'AWS Secret Key exposed in code',
    minEntropy: 4.2
  },
  {
    id: 'sec-google-api',
    name: 'Google Cloud / Gemini API Key',
    pattern: '\\bAIza[0-9A-Za-z\\-_]{35}\\b',
    flags: 'g',
    severity: 'HIGH',
    category: 'API_KEY',
    description: 'Google Cloud or Gemini API key exposed in source',
    minEntropy: 4.0
  },
  {
    id: 'sec-github-pat',
    name: 'GitHub Personal Access Token',
    pattern: '\\b(?:ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\\b',
    flags: 'g',
    severity: 'CRITICAL',
    category: 'AUTH_TOKEN',
    description: 'GitHub Personal Access Token found',
    minEntropy: 4.1
  },
  {
    id: 'sec-stripe-secret',
    name: 'Stripe Secret API Key',
    pattern: '\\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99}\\b',
    flags: 'g',
    severity: 'CRITICAL',
    category: 'API_KEY',
    description: 'Stripe secret or restricted key found in source',
    minEntropy: 4.0
  },
  {
    id: 'sec-jwt-token',
    name: 'JSON Web Token (JWT)',
    pattern: '\\beyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*\\b',
    flags: 'g',
    severity: 'HIGH',
    category: 'AUTH_TOKEN',
    description: 'Static JWT token found hardcoded',
    minEntropy: 4.3
  },
  {
    id: 'sec-db-uri',
    name: 'Database URI with Credentials',
    pattern: '(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql|redis):\\/\\/[^\\s:"\']+:[^\\s:"\']+@[^\\s:"\']+',
    flags: 'gi',
    severity: 'CRITICAL',
    category: 'DATABASE_URI',
    description: 'Database connection URI contains plain text password'
  },
  {
    id: 'sec-sensitive-api-path',
    name: 'Sensitive or Admin API Route',
    pattern: '[\'"](?:\\/api\\/v[0-9]+)?\\/(?:admin|internal|superadmin|debug|actuator|metrics|management|auth\\/token)[^\\s\'"]*[\'"]',
    flags: 'gi',
    severity: 'MEDIUM',
    category: 'API_PATH',
    description: 'Internal or privileged administrative endpoint path'
  }
];

function calculateEntropy(str) {
  if (!str) return 0;
  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function maskSecret(secret) {
  const clean = secret.trim().replace(/^['"]|['"]$/g, '');
  if (clean.length <= 8) return '••••••••';
  return `${clean.slice(0, 4)}••••••••${clean.slice(-4)}`;
}

function shouldIgnore(filePath, customIgnores = []) {
  const normalized = filePath.replace(/\\/g, '/');
  const ignorePatterns = [
    '/node_modules/', 'node_modules/',
    '/vendor/', 'vendor/',
    '/.git/', '.git/',
    '/dist/', 'dist/',
    '/build/', 'build/',
    '.min.js', '.bundle.js',
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'
  ];

  for (const p of [...ignorePatterns, ...customIgnores]) {
    if (normalized.includes(p)) return true;
  }
  return false;
}

function getFiles(dir, customIgnores = [], fileList = []) {
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

function run() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
🛡️  SecScan CLI - Static Analysis Secret & API Path Finder for CI/CD

Usage:
  secscan [target_directory] [options]

Options:
  --format <table|json|sarif|csv>   Output format (Default: table)
  --rules <file.json>               Path to custom regex rules JSON file
  --ignore <glob>                   Additional ignore patterns (comma-separated)
  --fail-on <critical|high|medium>  Fail CI build if severity is met
  --output <file>                   Write results directly to destination file
  --help                            Show this help message

Examples:
  secscan . --format json --output secscan-report.json
  secscan ./src --fail-on critical --format table
  secscan . --format sarif --output results.sarif
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

  let rules = [...DEFAULT_RULES];
  const rulesIdx = args.indexOf('--rules');
  if (rulesIdx !== -1 && args[rulesIdx + 1]) {
    try {
      const customRulesRaw = fs.readFileSync(args[rulesIdx + 1], 'utf-8');
      const parsedRules = JSON.parse(customRulesRaw);
      rules = [...rules, ...parsedRules];
    } catch (e) {
      console.error(`[SecScan Error] Failed to read rules file:`, e.message);
    }
  }

  const startTime = Date.now();
  const files = getFiles(path.resolve(targetDir), customIgnores);
  const findings = [];

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
      let match;
      while ((match = regex.exec(content)) !== null) {
        const full = match[0];
        const entropy = calculateEntropy(full);
        if (rule.minEntropy && entropy < rule.minEntropy) continue;

        const upToIndex = content.substring(0, match.index);
        const lineNum = upToIndex.split('\n').length;
        const lineText = (lines[lineNum - 1] || '').trim();

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
          snippet: lineText,
          description: rule.description
        });
      }
    }
  }

  const report = {
    scanner: "SecScan SAST v1.0.0",
    timestamp: new Date().toISOString(),
    targetDirectory: targetDir,
    totalFilesScanned: files.length,
    totalFindings: findings.length,
    findings,
    durationMs: Date.now() - startTime
  };

  let formattedOutput = '';
  if (format === 'json') {
    formattedOutput = JSON.stringify(report, null, 2);
  } else if (format === 'csv') {
    const header = 'ID,Severity,Rule,File,Line,Entropy,MaskedSecret\n';
    const rows = findings.map(f => `${f.id},${f.severity},"${f.ruleName}","${f.file}",${f.line},${f.entropy},"${f.maskedSecret}"`).join('\n');
    formattedOutput = header + rows;
  } else if (format === 'sarif') {
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: "SecScan", semanticVersion: "1.0.0" } },
        results: findings.map(f => ({
          ruleId: f.ruleId,
          level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
          message: { text: `[${f.ruleName}] ${f.description}` },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.line }
            }
          }]
        }))
      }]
    };
    formattedOutput = JSON.stringify(sarif, null, 2);
  } else {
    // Human readable table output
    const divider = '─'.repeat(80);
    console.log(`\n🛡️  SecScan Static Security Analysis Report`);
    console.log(divider);
    console.log(`Target: ${targetDir} | Scanned Files: ${files.length} | Findings: ${findings.length} | Elapsed: ${report.durationMs}ms`);
    console.log(divider);

    if (findings.length === 0) {
      console.log(`✅ No exposed secrets or sensitive API endpoints detected!\n`);
    } else {
      findings.forEach(f => {
        const tag = f.severity === 'CRITICAL' ? '🚨 CRITICAL' : f.severity === 'HIGH' ? '⚠️  HIGH' : '🟡 MEDIUM';
        console.log(`${tag.padEnd(12)} [${f.ruleName}]`);
        console.log(`  File:    ${f.file}:${f.line}`);
        console.log(`  Secret:  ${f.maskedSecret} (Entropy: ${f.entropy})`);
        console.log(`  Snippet: ${f.snippet}`);
        console.log(`  Info:    ${f.description}\n`);
      });
    }
  }

  if (outputFile) {
    fs.writeFileSync(path.resolve(outputFile), formattedOutput, 'utf-8');
    console.log(`[SecScan] Report successfully saved to: ${outputFile}`);
  } else if (format !== 'table') {
    console.log(formattedOutput);
  }

  // Check CI fail condition
  if (failOn) {
    const levels = ['MEDIUM', 'HIGH', 'CRITICAL'];
    const thresholdIdx = levels.indexOf(failOn);
    const hasFailingIssue = findings.some(f => {
      const idx = levels.indexOf(f.severity);
      return idx >= thresholdIdx;
    });

    if (hasFailingIssue) {
      console.error(`\n❌ [SecScan CI Failure] Found security issues meeting or exceeding severity threshold: ${failOn}`);
      process.exit(1);
    }
  }
}

run();
