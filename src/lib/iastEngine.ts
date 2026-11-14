import {
  IastHookSensor,
  IastVulnerabilityFinding,
  IastSimulationScenario,
  IastExecutionReport,
  IastTraceStep
} from '../types/iast';
import { ScannedFile, ScanReport } from '../types';

/**
 * Built-in IAST runtime hooks that instrument JavaScript/TypeScript sinks and sources
 */
export const INITIAL_IAST_HOOKS: IastHookSensor[] = [
  {
    id: 'hook-db-sql',
    name: 'SQL Query String Concatenation Interceptor',
    category: 'SQL_DATABASE_SINK',
    targetPackageOrGlobal: 'pg.query / mysql.query / sequelize.query',
    active: true,
    interceptedCallsCount: 0,
    vulnerabilitiesTriggeredCount: 0,
    description: 'Intercepta chamadas SQL no driver em runtime para verificar se fragmentos tainted de requisições HTTP chegam sem parametrização ($1 ou ?).'
  },
  {
    id: 'hook-cmd-exec',
    name: 'OS Command Execution Shell Interceptor',
    category: 'COMMAND_EXEC_SINK',
    targetPackageOrGlobal: 'child_process.exec / child_process.spawn',
    active: true,
    interceptedCallsCount: 0,
    vulnerabilitiesTriggeredCount: 0,
    description: 'Monitora a construção de strings de comando bash/sh/cmd passadas para exec(). Detecta caracteres de encadeamento não sanitizados (; | && $).'
  },
  {
    id: 'hook-path-traversal',
    name: 'File System Path Normalization Guard',
    category: 'FILE_SYSTEM_TRAVERSAL_SINK',
    targetPackageOrGlobal: 'fs.readFile / fs.createReadStream / path.join',
    active: true,
    interceptedCallsCount: 0,
    vulnerabilitiesTriggeredCount: 0,
    description: 'Rastreia caminhos de arquivos resolvidos dinamicamente comparando o diretório base pretendido com a saída de path.resolve().'
  },
  {
    id: 'hook-ssrf-fetch',
    name: 'Outbound HTTP SSRF Sinks Interceptor',
    category: 'SSRF_NETWORK_SINK',
    targetPackageOrGlobal: 'fetch / axios.get / http.request',
    active: true,
    interceptedCallsCount: 0,
    vulnerabilitiesTriggeredCount: 0,
    description: 'Valida URLs de requisições de saída em tempo de execução para barrar destinos em IP loopback (127.0.0.1, localhost) e metadados cloud (169.254.169.254).'
  },
  {
    id: 'hook-dom-eval',
    name: 'DOM Code Evaluator & Script Engine Hook',
    category: 'DOM_XSS_SINK',
    targetPackageOrGlobal: 'eval / Function() / document.write',
    active: true,
    interceptedCallsCount: 0,
    vulnerabilitiesTriggeredCount: 0,
    description: 'Mapeia dados recebidos de APIs e inputs de tela que chegam diretamente em avaliadores de código JavaScript dinâmico em tempo de execução.'
  },
  {
    id: 'hook-deserialization',
    name: 'Object Deserialization & Payload Hook',
    category: 'INSECURE_DESERIALIZATION_SINK',
    targetPackageOrGlobal: 'node-serialize / JSON.parse prototype / yaml.load',
    active: true,
    interceptedCallsCount: 0,
    vulnerabilitiesTriggeredCount: 0,
    description: 'Inspeciona serializações dinâmicas contra poluição de protótipo (__proto__) e instanciação arbitrária de classes não permitidas.'
  }
];

export const UNRESOLVED_SOURCE = 'origem não resolvida';

interface StaticSinkRule {
  category: IastHookSensor['category'];
  hookId: string;
  idPrefix: string;
  sink: RegExp;
  /** SQL and shell sinks only matter when the argument is built by concatenation or a template. */
  needsDynamicString: boolean;
  /** Report a non-literal argument even when its origin cannot be traced (code evaluators). */
  flagUnresolvedArgument?: boolean;
  title: string;
  cwe: { id: string; name: string };
  owaspCategory: string;
  severity: IastVulnerabilityFinding['severity'];
  explanation: string;
  remediationAdvice: string;
  secureExample: string;
}

const STATIC_SINK_RULES: StaticSinkRule[] = [
  {
    category: 'SQL_DATABASE_SINK',
    hookId: 'hook-db-sql',
    idPrefix: 'IAST-SQLI',
    sink: /\b[\w.]*\.(?:query|execute|raw)\s*\(/,
    needsDynamicString: true,
    title: 'Possível SQL Injection: dado da requisição concatenado em consulta',
    cwe: { id: 'CWE-89', name: 'Improper Neutralization of Special Elements used in an SQL Command' },
    owaspCategory: 'A03:2021 - Injection',
    severity: 'CRITICAL',
    explanation: 'A consulta é montada por concatenação ou template string, sem parâmetros ($1 ou ?).',
    remediationAdvice: 'Utilize consultas parametrizadas (Prepared Statements) em vez de template strings ou concatenação.',
    secureExample: '// Parametrização segura:\nawait db.query("SELECT * FROM items WHERE id = $1", [req.params.id]);'
  },
  {
    category: 'COMMAND_EXEC_SINK',
    hookId: 'hook-cmd-exec',
    idPrefix: 'IAST-CMDI',
    sink: /\b(?:child_process\.)?(?:execSync|exec|spawnSync|spawn)\s*\(/,
    needsDynamicString: true,
    title: 'Possível injeção de comando: dado da requisição em comando do sistema',
    cwe: { id: 'CWE-78', name: 'Improper Neutralization of Special Elements used in an OS Command' },
    owaspCategory: 'A03:2021 - Injection',
    severity: 'CRITICAL',
    explanation: 'O comando é montado como string e passa por um shell.',
    remediationAdvice: 'Evite child_process.exec com concatenação; prefira execFile ou spawn com argumentos em array estrito sem subshell.',
    secureExample: '// Execução com array de argumentos sem shell intermediário:\nexecFile("ping", ["-c", "3", sanitizedHost]);'
  },
  {
    category: 'FILE_SYSTEM_TRAVERSAL_SINK',
    hookId: 'hook-path-traversal',
    idPrefix: 'IAST-TRAVERSAL',
    sink: /\b(?:fs(?:\.promises)?\.(?:readFileSync|readFile|createReadStream|writeFileSync|writeFile|unlinkSync|unlink)|path\.(?:join|resolve)|res\.sendFile)\s*\(/,
    needsDynamicString: false,
    title: 'Possível Path Traversal: dado da requisição em caminho de arquivo',
    cwe: { id: 'CWE-22', name: 'Improper Limitation of a Pathname to a Restricted Directory' },
    owaspCategory: 'A01:2021 - Broken Access Control',
    severity: 'HIGH',
    explanation: 'O caminho depende de entrada do cliente e a linha não mostra contenção em um diretório base.',
    remediationAdvice: 'Valide se path.resolve(BASE_DIR, userInput).startsWith(BASE_DIR) antes de abrir arquivos.',
    secureExample: 'const safePath = path.resolve(BASE_DIR, path.basename(req.query.fileName));\nif (!safePath.startsWith(BASE_DIR)) throw new Error("Acesso negado");'
  },
  {
    category: 'SSRF_NETWORK_SINK',
    hookId: 'hook-ssrf-fetch',
    idPrefix: 'IAST-SSRF',
    sink: /\b(?:axios(?:\.(?:get|post|put|delete|patch|request))?|fetch|got|https?\.(?:request|get))\s*\(/,
    needsDynamicString: false,
    title: 'Possível SSRF: dado da requisição define o destino de uma chamada HTTP',
    cwe: { id: 'CWE-918', name: 'Server-Side Request Forgery (SSRF)' },
    owaspCategory: 'A10:2021 - Server-Side Request Forgery',
    severity: 'HIGH',
    explanation: 'O destino da chamada de saída vem do cliente e a linha não mostra allowlist de hosts.',
    remediationAdvice: 'Implemente verificação estrita de whitelist de domínios e bloqueie explicitamente IPs locais (127.0.0.1) e de metadados (169.254.169.254).',
    secureExample: 'const parsed = new URL(targetUrl);\nif (!ALLOWED_DOMAINS.includes(parsed.hostname)) throw new Error("Destino SSRF bloqueado");'
  },
  {
    category: 'DOM_XSS_SINK',
    hookId: 'hook-dom-eval',
    idPrefix: 'IAST-EVAL',
    sink: /\b(?:eval|new\s+Function|document\.write)\s*\(/,
    needsDynamicString: false,
    flagUnresolvedArgument: true,
    title: 'Possível injeção de código: valor dinâmico em avaliador de código',
    cwe: { id: 'CWE-95', name: 'Improper Neutralization of Directives in Dynamically Evaluated Code' },
    owaspCategory: 'A03:2021 - Injection',
    severity: 'HIGH',
    explanation: 'O valor é interpretado como código.',
    remediationAdvice: 'Elimine o uso de eval() ou Function(); utilize serialização estrita JSON.parse() ou Web Workers isolados.',
    secureExample: 'const config = JSON.parse(safePayloadData);'
  }
];

/** Server request data, plus the browser inputs an attacker controls. */
const REQUEST_SOURCE = /\b(?:req|request|ctx\.request|ctx)\.(?:body|query|params|headers|cookies)(?:\.[A-Za-z_$][\w$]*|\[['"][^'"\]]+['"]\])*|\b(?:window\.)?location\.(?:hash|search|href)|\bdocument\.(?:cookie|referrer|URL)|\bwindow\.name|\b(?:event|evt|e|message|msg)\.data(?:\.[A-Za-z_$][\w$]*)*/;

/** Keeps only the code of an expression: template `${}` contents stay, string literals go. */
function stripStringLiterals(expression: string): string {
  return expression
    .replace(/`(?:[^`\\]|\\.)*`/g, (template) => ` ${[...template.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1]).join(' ')} `)
    .replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, '""');
}

interface TaintOrigin {
  /** Request expression the value comes from, e.g. req.query.id. */
  source: string;
  line: number;
}

/**
 * Variables assigned from the HTTP request inside one file, including
 * destructuring and one level of reassignment. It is a per-file approximation:
 * it does not follow calls into other files.
 */
export function collectRequestTaint(lines: string[]): Map<string, TaintOrigin> {
  const tainted = new Map<string, TaintOrigin>();
  lines.forEach((raw, idx) => {
    const line = raw.trim();
    if (!line || line.startsWith('//') || line.startsWith('*')) return;

    const destructured = line.match(/\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$/);
    if (destructured) {
      const source = destructured[2].match(REQUEST_SOURCE);
      if (source) {
        for (const part of destructured[1].split(',')) {
          const [key, alias] = part.split(':').map((piece) => piece.trim().split('=')[0].trim());
          const name = (alias || key || '').replace(/^\.\.\./, '');
          if (/^[A-Za-z_$][\w$]*$/.test(name)) tainted.set(name, { source: `${source[0]}.${key.replace(/^\.\.\./, '')}`, line: idx + 1 });
        }
      }
      return;
    }

    const assigned = line.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(.+)$/);
    if (!assigned) return;
    const direct = assigned[2].match(REQUEST_SOURCE);
    if (direct) {
      tainted.set(assigned[1], { source: direct[0], line: idx + 1 });
      return;
    }
    for (const [name, origin] of tainted) {
      if (new RegExp(`(?<![\\w$.'"])${name.replace(/\$/g, '\\$')}(?![\\w$'"])`).test(assigned[2])) {
        tainted.set(assigned[1], { source: origin.source, line: idx + 1 });
        break;
      }
    }
  });
  return tainted;
}

function findTaintInExpression(
  expression: string,
  taintedVars: Map<string, TaintOrigin>,
  lineNum: number
): { variable: string; source: string; sourceLine: number } | null {
  // String literals are data, not variable references.
  const code = stripStringLiterals(expression);
  const direct = code.match(REQUEST_SOURCE);
  if (direct) return { variable: direct[0], source: direct[0], sourceLine: lineNum };
  for (const [name, origin] of taintedVars) {
    if (origin.line >= lineNum) continue;
    if (new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}(?![\\w$])`).test(code)) {
      return { variable: name, source: origin.source, sourceLine: origin.line };
    }
  }
  return null;
}

/**
 * Static taint analysis over the workspace files. Despite the historical name,
 * it executes nothing: it follows request data to dangerous calls inside each
 * file and reports the real source and sink lines. `customScenario` is ignored:
 * replaying a payload needs an agent inside the running application.
 */
export function runIastRuntimeEmulation(
  files: ScannedFile[],
  activeHooks: IastHookSensor[],
  customScenario?: IastSimulationScenario,
  existingDangerousSinks?: any[],
  existingEndpoints?: any[]
): IastExecutionReport {
  const sessionId = 'iast-session-' + Date.now();
  const timestamp = new Date().toLocaleTimeString();

  // If no workspace files, return clean empty report (zero mock leaks)
  if (!files || files.length === 0) {
    return {
      sessionId,
      timestamp,
      status: 'IDLE',
      totalEmulatedRequests: 0,
      totalHooksTriggered: 0,
      findings: [],
      activeHooks: activeHooks.map(h => ({
        ...h,
        interceptedCallsCount: 0,
        vulnerabilitiesTriggeredCount: 0
      })),
      coverageMetrics: {
        endpointsInstrumented: 0,
        sinksCovered: 0,
        taintPropagationSuccessRate: 0,
        falsePositiveReductionPercent: 0,
        avgInspectionOverheadMs: 0
      }
    };
  }

  const activeHookCategories = new Set(activeHooks.filter(h => h.active).map(h => h.category));
  const activeFiles = files.filter(f => !f.isIgnored && Boolean(f.content));

  // Map of category -> hook count tracker
  const interceptedMap = new Map<string, number>();
  const triggeredMap = new Map<string, number>();
  activeHooks.forEach(h => {
    interceptedMap.set(h.category, 0);
    triggeredMap.set(h.category, 0);
  });

  // Extract endpoints from workspace or use provided
  const endpointsList: { file: string; path: string; method: string }[] = [];
  if (Array.isArray(existingEndpoints) && existingEndpoints.length > 0) {
    existingEndpoints.forEach(ep => {
      if (ep.path) {
        endpointsList.push({ file: ep.file || '', path: ep.path, method: ep.method || 'GET' });
      }
    });
  } else {
    for (const f of activeFiles) {
      const routeRegex = /(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
      let match: RegExpExecArray | null;
      while ((match = routeRegex.exec(f.content)) !== null) {
        endpointsList.push({
          file: f.path,
          method: match[1].toUpperCase(),
          path: match[2]
        });
      }
    }
  }

  const discoveredFindings: IastVulnerabilityFinding[] = [];

  for (const file of activeFiles) {
    const ext = (file.extension || file.name.split('.').pop() || '').toLowerCase();
    if (!['js', 'ts', 'jsx', 'tsx', 'mjs', 'cjs'].includes(ext)) continue;

    const lines = file.content.split('\n');
    const taintedVars = collectRequestTaint(lines);
    const fileEndpoints = endpointsList.filter(e => e.file === file.path);

    lines.forEach((lineText, lineIdx) => {
      const lineNum = lineIdx + 1;
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) return;

      for (const rule of STATIC_SINK_RULES) {
        if (!activeHookCategories.has(rule.category)) continue;
        const sinkMatch = trimmed.match(rule.sink);
        if (!sinkMatch) continue;
        interceptedMap.set(rule.category, (interceptedMap.get(rule.category) || 0) + 1);

        const argument = trimmed.slice((sinkMatch.index || 0) + sinkMatch[0].length);
        if (rule.needsDynamicString && !/[+`]|\$\{/.test(argument)) continue;
        const traced = findTaintInExpression(argument, taintedVars, lineNum);
        const dynamicArgument = (stripStringLiterals(argument).match(/^\s*([A-Za-z_$][\w$.]*)/) || [])[1];
        const taint = traced || (rule.flagUnresolvedArgument && dynamicArgument
          ? { variable: dynamicArgument, source: UNRESOLVED_SOURCE, sourceLine: lineNum }
          : null);
        if (!taint) continue;

        triggeredMap.set(rule.category, (triggeredMap.get(rule.category) || 0) + 1);
        const sinkFunction = `${sinkMatch[0].replace(/\s*\($/, '')}()`;
        const endpoint = fileEndpoints.length === 1 ? fileEndpoints[0] : undefined;
        const evidence = trimmed.slice(0, 180);

        const tracePath: IastTraceStep[] = [];
        if (taint.sourceLine !== lineNum) {
          tracePath.push({
            stepIndex: 1,
            hookId: 'hook-http-source',
            hookCategory: 'HTTP_REQUEST_SOURCE',
            file: file.path,
            line: taint.sourceLine,
            functionName: endpoint ? `${endpoint.method} ${endpoint.path}` : '',
            variableName: taint.variable,
            runtimeValue: lines[taint.sourceLine - 1].trim().slice(0, 120),
            isTainted: true,
            description: `A variável ${taint.variable} recebe ${taint.source} nesta linha.`
          });
        }
        tracePath.push({
          stepIndex: tracePath.length + 1,
          hookId: rule.hookId,
          hookCategory: rule.category,
          file: file.path,
          line: lineNum,
          functionName: sinkFunction,
          variableName: taint.variable,
          runtimeValue: trimmed.slice(0, 120),
          isTainted: true,
          description: `${taint.variable} chega a ${sinkFunction} sem tratamento visível na linha.`
        });

        discoveredFindings.push({
          id: `${rule.idPrefix}-${file.path}-${lineNum}`,
          title: rule.title,
          cwe: rule.cwe,
          owaspCategory: rule.owaspCategory,
          severity: rule.severity,
          // Static match inside one file. Nothing was executed, so it stays a suspicion.
          confidence: !traced ? 40 : taint.sourceLine === lineNum ? 70 : 60,
          status: 'SUSPECTED',
          sourceEndpoint: endpoint ? endpoint.path : '',
          httpMethod: (endpoint ? endpoint.method : 'GET') as IastVulnerabilityFinding['httpMethod'],
          taintedParameter: taint.source,
          simulatedPayload: '',
          sinkFunction,
          sinkFile: file.path,
          sinkLine: lineNum,
          vulnerabilityExplanation: !traced
            ? `Análise estática: ${sinkFunction} recebe o valor dinâmico ${taint.variable} em ${file.path}:${lineNum}. A origem desse valor não foi resolvida dentro do arquivo. ${rule.explanation} Nenhuma requisição foi executada: confirme de onde o valor vem.`
            : `Análise estática: ${taint.source} ${taint.sourceLine === lineNum ? 'é usado diretamente' : `é atribuído a ${taint.variable} na linha ${taint.sourceLine} e chega`} em ${sinkFunction} (${file.path}:${lineNum}). ${rule.explanation} Nenhuma requisição foi executada: confirme em um ambiente de teste.`,
          runtimeEvidence: {
            executedQueryOrCommand: evidence,
            unfilteredTaintSubstring: taint.variable,
            runtimeDurationMs: 0
          },
          tracePath,
          runtimeCallStack: [],
          remediationAdvice: rule.remediationAdvice,
          remediationCodeExample: { vulnerable: trimmed, secure: rule.secureExample }
        });
      }
    });
  }

  const findings = Array.from(new Map(discoveredFindings.map(f => [f.id, f])).values());

  // Update activeHooks with real counts
  const updatedHooks: IastHookSensor[] = activeHooks.map(h => ({
    ...h,
    interceptedCallsCount: interceptedMap.get(h.category) || 0,
    vulnerabilitiesTriggeredCount: triggeredMap.get(h.category) || 0
  }));

  const totalIntercepted = updatedHooks.reduce((acc, h) => acc + h.interceptedCallsCount, 0);

  return {
    sessionId,
    timestamp,
    status: 'COMPLETED',
    totalEmulatedRequests: 0,
    totalHooksTriggered: totalIntercepted,
    findings,
    activeHooks: updatedHooks,
    coverageMetrics: {
      endpointsInstrumented: endpointsList.length,
      sinksCovered: updatedHooks.filter(h => h.active).length,
      taintPropagationSuccessRate: totalIntercepted > 0 ? Math.round((findings.length / totalIntercepted) * 100) : 0,
      falsePositiveReductionPercent: 0,
      avgInspectionOverheadMs: 0
    }
  };
}
