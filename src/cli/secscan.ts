#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { DEFAULT_RULES } from '../lib/defaultRules';
import { scanSoftwareCompositionAnalysis } from '../lib/scaScanner';
import { scanInfrastructureAsCode } from '../lib/iacScanner';
import { scanWorkspaceEntropy } from '../lib/entropyScanner';
import { extractLinkFinderEndpoints } from '../lib/linkFinderEngine';
import { evaluateSecurityHeaders } from '../lib/securityHeadersEngine';
import { auditJwtToken } from '../lib/jwtInspectorEngine';
import { validateSsrfTarget } from '../lib/ssrfValidatorEngine';
import { auditDockerfile } from '../lib/containerSecurityEngine';
import { auditIamPolicy } from '../lib/cloudIamEngine';
import { generateCycloneDxSbom } from '../lib/sbomGenerator';
import { evaluateComplianceReadiness } from '../lib/complianceEngine';
import type { ScannedFile, ScanFinding } from '../types';

const TOOLS = new Set([
  'scan', 'sca', 'iac', 'entropy', 'endpoints', 'headers', 'jwt', 'ssrf', 'dockerfile', 'iam', 'sbom', 'compliance',
]);

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

function printHelp(): void {
  console.log(`
SecScan CLI

Usage:
  secscan [scan] [directory] [options]
  secscan <tool> <target>

Tools that read your files:
  scan          Static rules from src/lib/defaultRules.ts. Default when the first argument is a directory.
  sca           package.json and requirements.txt against the local catalog
  iac           Dockerfile, Compose, Kubernetes and Terraform
  entropy       High-entropy quoted tokens
  endpoints     Paths mined from source
  headers       A text file of response headers (Name: value)
  jwt           One JWT string
  ssrf          One URL, classified without sending a request
  dockerfile    One Dockerfile
  iam           One IAM policy JSON file
  sbom          CycloneDX from the manifests. Hashes are placeholders, not file digests
  compliance    Readiness from the same static findings as scan

Laboratory screens (Nmap, DAST, IAST, EDR, SOC, threat intel) have no CLI. They do not scan a target.

Options:
  --format <table|json|sarif|csv>   Output format (Default: table). sarif and csv apply to scan
  --rules <file.json>               Extra regex rules, added to the defaults (scan, compliance)
  --ignore <patterns>               Extra ignore fragments, comma-separated
  --fail-on <critical|high|medium>  Exit 1 when a scan finding meets the severity
  --max-risk <score>                Exit 1 when the scan risk score exceeds the threshold
  --output <file>                   Write the report to a file
  --help                            Show this help message
`);
}

function positional(args: string[]): string | undefined {
  return args.find((arg) => !arg.startsWith('--'));
}

function flag(args: string[], name: string): string | null {
  const index = args.indexOf(name);
  return index !== -1 && args[index + 1] ? args[index + 1] : null;
}

function walkFiles(dir: string, accept: (name: string) => boolean, bucket: string[] = []): string[] {
  if (!fs.existsSync(dir)) return bucket;
  const stat = fs.statSync(dir);
  if (stat.isFile()) {
    if (accept(path.basename(dir))) bucket.push(dir);
    return bucket;
  }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (shouldIgnore(fullPath)) continue;
    if (entry.isDirectory()) walkFiles(fullPath, accept, bucket);
    else if (accept(entry.name)) bucket.push(fullPath);
  }
  return bucket;
}

function toScanned(filePath: string): ScannedFile {
  const content = fs.readFileSync(filePath, 'utf8');
  return {
    name: path.basename(filePath),
    path: path.relative(process.cwd(), filePath) || filePath,
    content,
    size: Buffer.byteLength(content),
    extension: path.extname(filePath).replace(/^\./, '') || path.basename(filePath),
  };
}

function emit(lines: string[], payload: unknown, args: string[]): void {
  const format = flag(args, '--format') || 'table';
  const outputFile = flag(args, '--output');
  const text = format === 'json' ? JSON.stringify(payload, null, 2) : lines.join('\n');
  if (outputFile) fs.writeFileSync(outputFile, text);
  else console.log(text);
}

function readText(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[SecScan] Não foi possível ler ${filePath}: ${message}`);
    process.exit(1);
  }
}

function requireTarget(args: string[], usage: string): string {
  const target = positional(args);
  if (!target) {
    console.error(`[SecScan] Falta o alvo. ${usage}`);
    process.exit(1);
  }
  return target;
}

function runTool(command: string, args: string[]): void {
  if (command === 'sca' || command === 'sbom' || command === 'entropy' || command === 'endpoints' || command === 'iac') {
    const dir = path.resolve(requireTarget(args, `secscan ${command} <diretório>`));
    if (command === 'sca' || command === 'sbom') {
      const files = walkFiles(dir, (name) => /^(package\.json|requirements\.txt)$/i.test(name)).map(toScanned);
      if (command === 'sca') {
        const report = scanSoftwareCompositionAnalysis(files);
        emit([
          `SCA  pacotes=${report.totalDependencies}  vulneráveis=${report.vulnerableCount}  catálogo=${report.catalogMode} (${report.catalogSize})`,
          'A licença ausente do catálogo local fica NOT_IN_CATALOG. Esta chamada não consulta o OSV.',
          ...report.packages.map((pkg) => `${pkg.name}@${pkg.version}  ${pkg.license}  vulns=${pkg.vulnerabilities.length}  ${pkg.manifestFile}`),
        ], report, args);
        return;
      }
      const sbom = generateCycloneDxSbom(files);
      emit([
        `SBOM ${sbom.format} ${sbom.version}  componentes=${sbom.totalComponents}  ${sbom.appName}@${sbom.appVersion}`,
        'Os hashes deste SBOM são placeholders determinísticos, não o digest dos arquivos.',
        ...sbom.components.map((component) => `${component.purl}  license=${component.license}  vulns=${component.vulnerabilitiesCount}`),
      ], sbom, args);
      return;
    }
    if (command === 'iac') {
      const files = walkFiles(dir, (name) => /^(dockerfile|containerfile)$|\.dockerfile$|\.(ya?ml|tf|tfvars)$/i.test(name)).map(toScanned);
      const report = scanInfrastructureAsCode(files);
      emit([
        `IaC  arquivos=${report.totalFilesScanned}  falhas=${report.failedChecks}  postura=${report.iacPostureScore}`,
        ...report.findings.map((finding) => `${finding.severity.padEnd(8)} ${finding.title}  ${finding.file}:${finding.line}`),
      ], report, args);
      return;
    }
    if (command === 'entropy') {
      const files = walkFiles(dir, (name) => /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(name)).map(toScanned);
      const report = scanWorkspaceEntropy(files);
      emit([
        `Entropia  tokens=${report.totalTokensScanned}  altos=${report.highEntropyFindings.length}  pico=${report.highestEntropyObserved}`,
        ...report.highEntropyFindings.map((finding) => `${finding.entropyLevel.padEnd(8)} ${finding.entropy}  ${finding.file}:${finding.line}  ${finding.maskedToken}`),
      ], report, args);
      return;
    }
    const files = walkFiles(dir, (name) => /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(name)).map(toScanned);
    const endpoints = files.flatMap((file) => extractLinkFinderEndpoints(file.path, file.content));
    emit([
      `Endpoints  ${endpoints.length}`,
      ...endpoints.map((endpoint) => `${(endpoint.method || 'UNKNOWN').padEnd(7)} ${endpoint.path}  ${endpoint.file}:${endpoint.line}`),
    ], { total: endpoints.length, endpoints }, args);
    return;
  }

  if (command === 'headers') {
    const filePath = requireTarget(args, 'secscan headers <arquivo>');
    const text = readText(filePath);
    const headers: Record<string, string> = {};
    for (const line of text.split(/\r?\n/)) {
      const splitAt = line.indexOf(':');
      if (splitAt <= 0) continue;
      const name = line.slice(0, splitAt).trim();
      if (!name || name.startsWith('HTTP/')) continue;
      headers[name] = line.slice(splitAt + 1).trim();
    }
    const report = evaluateSecurityHeaders(headers, filePath);
    emit([
      `Headers  nota=${report.grade}  score=${report.totalScore}`,
      ...report.headersEvaluated.map((item) => `${item.status.padEnd(10)} ${item.headerName}`),
    ], report, args);
    return;
  }

  if (command === 'jwt') {
    const token = requireTarget(args, 'secscan jwt <token>');
    const report = auditJwtToken(token);
    emit([
      `JWT  alg=${report.algorithm}  expirado=${report.isExpired}  vulnerabilidades=${report.vulnerabilities.length}`,
      ...report.vulnerabilities.map((item) => `${item.severity.padEnd(8)} ${item.title}`),
    ], report, args);
    return;
  }

  if (command === 'ssrf') {
    const url = requireTarget(args, 'secscan ssrf <url>');
    const report = validateSsrfTarget(url);
    emit([
      `SSRF  ${report.riskLevel}  ${report.classification}`,
      report.attackTechnique,
      'Nenhuma requisição foi enviada. Isto só classifica a URL.',
    ], report, args);
    return;
  }

  if (command === 'dockerfile') {
    const filePath = requireTarget(args, 'secscan dockerfile <Dockerfile>');
    const report = auditDockerfile(readText(filePath), path.basename(filePath));
    emit([
      `Dockerfile  ${report.imageOrDockerfileName}  ${report.status}  score=${report.totalScore}`,
      ...report.findings.map((finding) => `${finding.severity.padEnd(8)} ${finding.title}`),
    ], report, args);
    return;
  }

  if (command === 'iam') {
    const filePath = requireTarget(args, 'secscan iam <politica.json>');
    const report = auditIamPolicy(readText(filePath), path.basename(filePath));
    emit([
      `IAM  ${report.policyName}  ${report.posture}  score=${report.riskScore}`,
      ...report.findings.map((finding) => `${finding.severity.padEnd(8)} ${finding.title}`),
    ], report, args);
    return;
  }

  const dir = path.resolve(requireTarget(args, 'secscan compliance <diretório>'));
  let rules = DEFAULT_RULES.filter((rule) => rule.enabled !== false);
  const rulesFile = flag(args, '--rules');
  if (rulesFile) {
    try {
      const parsedRules = JSON.parse(readText(rulesFile));
      if (!Array.isArray(parsedRules)) throw new Error('o arquivo precisa ser uma lista de regras');
      rules = [...rules, ...parsedRules];
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[SecScan] Não foi possível ler as regras: ${message}`);
      process.exit(1);
    }
  }
  const customIgnores = (flag(args, '--ignore') || '').split(',').map((item) => item.trim()).filter(Boolean);
  const findings = collectFindings(dir, customIgnores, rules);
  const assessment = evaluateComplianceReadiness(findings.map(toScanFinding));
  const frameworks = Object.values(assessment.frameworkSummaries);
  emit([
    `Compliance  prontidão=${assessment.overallReadinessPercentage}%  ${assessment.overallStatus}  achados=${findings.length}`,
    ...frameworks.map((framework) => `${framework.name.padEnd(22)} ${String(framework.readinessPercentage).padStart(3)}%  ${framework.status}`),
  ], assessment, args);
}

function toScanFinding(finding: CliFinding): ScanFinding {
  return {
    id: finding.id,
    ruleId: finding.ruleId,
    ruleName: finding.ruleName,
    category: finding.category as ScanFinding['category'],
    severity: finding.severity as ScanFinding['severity'],
    file: finding.file,
    line: finding.line,
    column: 1,
    snippet: finding.snippet,
    matchedSecret: finding.matchedSecret,
    maskedSecret: finding.maskedSecret,
    entropy: finding.entropy,
    description: finding.description,
    remediation: '',
    timestamp: new Date().toISOString(),
  };
}

function collectFindings(targetDir: string, customIgnores: string[], rules: typeof DEFAULT_RULES): CliFinding[] {
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
  return findings;
}

function run(): void {
  const raw = process.argv.slice(2);

  if (raw.includes('--help') || raw.includes('-h')) {
    printHelp();
    process.exit(0);
  }

  const command = raw[0] && TOOLS.has(raw[0]) ? raw[0] : 'scan';
  const args = command === 'scan' && raw[0] && TOOLS.has(raw[0]) ? raw.slice(1) : (command === 'scan' ? raw : raw.slice(1));
  if (command !== 'scan') {
    runTool(command, args);
    return;
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
  const findings = collectFindings(targetDir, customIgnores, rules);

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
