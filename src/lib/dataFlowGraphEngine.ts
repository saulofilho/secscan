import {
  ScannedFile,
  ApiEndpointFinding,
  DangerousSinkFinding,
  DataFlowNode,
  DataFlowLink,
  DataFlowGraphData,
  TaintVariableFlow,
  SeverityLevel
} from '../types';

export interface ExtractedFunction {
  id: string;
  name: string;
  file: string;
  startLine: number;
  endLine: number;
  snippet: string;
  body: string;
  isAsync: boolean;
  calls: string[];
}

/**
 * CWE and Threat taxonomy mappings for dangerous sinks
 */
const SINK_TAXONOMY: Record<
  DangerousSinkFinding['sinkType'],
  {
    cwe: { id: string; name: string };
    riskCategory: string;
    threatDescription: string;
  }
> = {
  EVAL: {
    cwe: { id: 'CWE-94', name: 'Improper Control of Generation of Code (Code Injection)' },
    riskCategory: 'DOM Code Execution (CWE-94)',
    threatDescription: 'Fluxo direto de endpoint de API para eval(). Permite execução remota de scripts e bypass total da sandbox.'
  },
  FUNCTION_CONSTRUCTOR: {
    cwe: { id: 'CWE-95', name: 'Improper Neutralization of Directives in Dynamically Evaluated Code' },
    riskCategory: 'Dynamic Function Injection (CWE-95)',
    threatDescription: 'Instanciação dinâmica de funções com dados provindos de APIs. Equivalente a eval() arbitrário.'
  },
  INNER_HTML: {
    cwe: { id: 'CWE-79', name: 'Improper Neutralization of Input During Web Page Generation (DOM-based XSS)' },
    riskCategory: 'DOM-based Cross-site Scripting (CWE-79)',
    threatDescription: 'Resposta de endpoint injetada diretamente em innerHTML/outerHTML sem sanitização DOMPurify.'
  },
  DOCUMENT_WRITE: {
    cwe: { id: 'CWE-79', name: 'Cross-site Scripting via document.write()' },
    riskCategory: 'Legacy DOM-based XSS (CWE-79)',
    threatDescription: 'Chamada a document.write() utilizando dados de rede ou query params do usuário.'
  },
  POST_MESSAGE: {
    cwe: { id: 'CWE-345', name: 'Insufficient Verification of Data Authenticity (Wildcard postMessage)' },
    riskCategory: 'Cross-Window Data Leakage (CWE-345)',
    threatDescription: 'Dados de API ou tokens de sessão transmitidos via postMessage com targetOrigin "*", capturáveis por iframes maliciosos.'
  },
  INSECURE_STORAGE: {
    cwe: { id: 'CWE-312', name: 'Cleartext Storage of Sensitive Information in LocalStorage' },
    riskCategory: 'Insecure Client Storage (CWE-312)',
    threatDescription: 'Tokens de sessão ou credenciais obtidas via API persistidas em localStorage/sessionStorage.'
  }
};

const ALLOWED_CODE_EXTENSIONS = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'py', 'php', 'rb', 'go']);

/**
 * Extracts functions from source code with line ranges and body content safely
 */
export function extractFunctionsFromSource(file: ScannedFile): ExtractedFunction[] {
  const content = file.content;
  if (!content) return [];

  // 1. Skip non-code files (HTML, JSON, markdown, styles, etc.) to prevent expensive parsing stalls
  const fileName = (file.name || '').toLowerCase();
  const ext = fileName.split('.').pop() || '';
  if (!ALLOWED_CODE_EXTENSIONS.has(ext)) {
    return [];
  }

  const lines = content.split('\n');
  const functions: ExtractedFunction[] = [];

  // Minified file heuristic: very long single lines or few lines for massive content
  const isMinified = lines.length <= 5 && content.length > 30000;
  const maxFunctionsToExtract = isMinified ? 12 : 30;

  // Patterns for function declarations and methods
  const FUNCTION_HEADER_PATTERNS = [
    // async function name(...) or function name(...)
    /(?:async\s+)?function\s+([a-zA-Z0-9_$]{2,40})\s*\(([^)]*)\)/g,
    // const/let/var name = async (...) => or name = (...) =>
    /(?:const|let|var)\s+([a-zA-Z0-9_$]{2,40})\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|[a-zA-Z0-9_$]{2,40})\s*=>/g,
    // const/let/var name = async function(...)
    /(?:const|let|var)\s+([a-zA-Z0-9_$]{2,40})\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)/g,
    // static async methodName(...) or async methodName(...)
    /(?:static\s+)?(?:async\s+)?([a-zA-Z0-9_$]{2,40})\s*\(([^)]*)\)\s*\{/g,
    // router.post('/path', async (req, res) => ...)
    /(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g
  ];

  const maxLinesToScan = Math.min(lines.length, 3000);

  for (let i = 0; i < maxLinesToScan; i++) {
    if (functions.length >= maxFunctionsToExtract) break;

    let lineText = lines[i];
    // Safeguard for minified code: truncate long lines to 800 chars for regex scanning
    if (lineText.length > 800) {
      lineText = lineText.substring(0, 800);
    }

    // Check for route handler: router.post('/path', ...)
    const routeMatch = /(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/i.exec(lineText);
    if (routeMatch) {
      const method = routeMatch[1].toUpperCase();
      const routePath = routeMatch[2];
      const fnName = `RouteHandler: ${method} ${routePath}`;
      const startLine = i + 1;
      const { endLine, body } = estimateFunctionBlock(lines, i, isMinified);

      functions.push({
        id: `fn-${file.path}-${startLine}-${functions.length}`,
        name: fnName,
        file: file.path,
        startLine,
        endLine,
        snippet: lineText.trim().substring(0, 200),
        body,
        isAsync: lineText.includes('async'),
        calls: extractCallsFromBody(body)
      });
      continue;
    }

    // Standard function declarations
    for (const pattern of FUNCTION_HEADER_PATTERNS) {
      pattern.lastIndex = 0;
      const match = pattern.exec(lineText);
      if (match && match[1]) {
        const fnName = match[1];
        // Skip common keywords mistakenly captured or 1-character minified tokens
        if (fnName.length < 2 || ['if', 'for', 'while', 'switch', 'catch', 'constructor'].includes(fnName)) {
          continue;
        }

        const startLine = i + 1;
        // Avoid duplicate start line
        if (functions.some(f => f.file === file.path && f.startLine === startLine)) {
          continue;
        }

        const { endLine, body } = estimateFunctionBlock(lines, i, isMinified);

        functions.push({
          id: `fn-${file.path}-${startLine}-${fnName}`,
          name: fnName,
          file: file.path,
          startLine,
          endLine,
          snippet: lineText.trim().substring(0, 200),
          body,
          isAsync: lineText.includes('async'),
          calls: extractCallsFromBody(body)
        });
        break;
      }
    }
  }

  return functions;
}

/**
 * Estimates the closing line of a function block by counting braces safely
 */
function estimateFunctionBlock(lines: string[], startIdx: number, isMinified = false): { endLine: number; body: string } {
  if (isMinified) {
    const rawLine = lines[startIdx] || '';
    return { endLine: startIdx + 1, body: rawLine.substring(0, 600) };
  }

  let openBraces = 0;
  let hasOpened = false;
  let endIdx = startIdx;
  const maxScanLines = Math.min(lines.length, startIdx + 120);

  for (let i = startIdx; i < maxScanLines; i++) {
    const line = lines[i];
    const scanLimit = Math.min(line.length, 500);

    for (let c = 0; c < scanLimit; c++) {
      const ch = line[c];
      if (ch === '{') {
        openBraces++;
        hasOpened = true;
      } else if (ch === '}') {
        openBraces--;
      }
    }

    if (hasOpened && openBraces <= 0) {
      endIdx = i;
      break;
    }
  }

  const body = lines.slice(startIdx, Math.min(endIdx + 1, startIdx + 60)).join('\n').substring(0, 2500);
  return { endLine: endIdx + 1, body };
}

/**
 * Extracts calls to other functions or API clients from function body safely
 */
function extractCallsFromBody(body: string): string[] {
  const calls: Set<string> = new Set();
  const boundedBody = body.substring(0, 2000);
  const callRegex = /\b([a-zA-Z0-9_$]{3,35})\s*\(/g;
  let m: RegExpExecArray | null;

  while ((m = callRegex.exec(boundedBody)) !== null && calls.size < 15) {
    const called = m[1];
    if (
      !['if', 'for', 'while', 'switch', 'catch', 'return', 'require', 'import', 'console', 'log'].includes(called)
    ) {
      calls.add(called);
    }
  }

  return Array.from(calls);
}

/**
 * Builds the complete Data Flow Graph mapping:
 * Endpoints -> Consumer Functions -> Dangerous Sinks
 */
export function buildDataFlowGraph(
  files: ScannedFile[],
  apiEndpoints: ApiEndpointFinding[],
  dangerousSinks: DangerousSinkFinding[]
): DataFlowGraphData {
  try {
    const activeFiles = files.filter(f => !f.isIgnored);
  const nodesMap: Map<string, DataFlowNode> = new Map();
  const links: DataFlowLink[] = [];

  // 1. Extract all consumer functions across active files
  const allFunctions: ExtractedFunction[] = [];
  for (const file of activeFiles) {
    const fns = extractFunctionsFromSource(file);
    allFunctions.push(...fns);
  }

  // 2. Register Endpoints as Source Nodes
  const endpointNodes: DataFlowNode[] = [];
  for (const ep of apiEndpoints) {
    const cleanPath = ep.path.length > 40 ? ep.path.substring(0, 37) + '...' : ep.path;
    const methodStr = ep.method || 'GET';
    const nodeId = `ep-${ep.file}-${ep.line}-${ep.path}`;

    if (!nodesMap.has(nodeId)) {
      const node: DataFlowNode = {
        id: nodeId,
        type: 'ENDPOINT',
        label: cleanPath,
        sublabel: `${methodStr} • ${ep.scope || 'API'}`,
        file: ep.file,
        line: ep.line,
        method: methodStr,
        urlType: ep.urlType,
        scope: ep.scope,
        isInternalOrAdmin: ep.isInternalOrAdmin,
        snippet: ep.snippet,
        description: `Endpoint ${methodStr} detectado pelo LinkFinder/JS-Miner em ${ep.file}:${ep.line}.`,
        tainted: false,
        connectionsCount: 0
      };
      nodesMap.set(nodeId, node);
      endpointNodes.push(node);
    }
  }

  // 3. Register Consumer Functions as Intermediate Nodes
  const consumerNodes: DataFlowNode[] = [];
  for (const fn of allFunctions) {
    const nodeId = fn.id;
    if (!nodesMap.has(nodeId)) {
      const node: DataFlowNode = {
        id: nodeId,
        type: 'CONSUMER',
        label: `${fn.name}()`,
        sublabel: `${fn.file.split('/').pop()}:${fn.startLine}`,
        file: fn.file,
        line: fn.startLine,
        snippet: fn.snippet,
        description: `Função de consumo/controlador ${fn.name}() em ${fn.file} (linhas ${fn.startLine}-${fn.endLine}).`,
        tainted: false,
        connectionsCount: 0
      };
      nodesMap.set(nodeId, node);
      consumerNodes.push(node);
    }
  }

  // 4. Register Dangerous Sinks as Target Nodes
  const sinkNodes: DataFlowNode[] = [];
  for (const sink of dangerousSinks) {
    const nodeId = `sink-${sink.id}`;
    const taxonomy = SINK_TAXONOMY[sink.sinkType] || {
      cwe: { id: 'CWE-20', name: 'Improper Input Handling' },
      riskCategory: 'Dangerous Sink',
      threatDescription: sink.description
    };

    if (!nodesMap.has(nodeId)) {
      const node: DataFlowNode = {
        id: nodeId,
        type: 'SINK',
        label: sink.sinkType,
        sublabel: `${sink.severity} • Linha ${sink.line}`,
        file: sink.file,
        line: sink.line,
        sinkType: sink.sinkType,
        severity: sink.severity,
        snippet: sink.snippet,
        description: sink.description,
        remediation: sink.remediation,
        riskCategory: taxonomy.riskCategory,
        cwe: taxonomy.cwe,
        tainted: false,
        connectionsCount: 0
      };
      nodesMap.set(nodeId, node);
      sinkNodes.push(node);
    }
  }

  // Helper to add links without duplicate
  const addLink = (sourceId: string, targetId: string, flowType: DataFlowLink['flowType'], isTainted: boolean, file: string, label?: string) => {
    const linkId = `${sourceId}__TO__${targetId}`;
    if (!links.some(l => l.id === linkId)) {
      links.push({
        id: linkId,
        source: sourceId,
        target: targetId,
        flowType,
        isTainted,
        label,
        file
      });

      const sNode = nodesMap.get(sourceId);
      if (sNode) sNode.connectionsCount = (sNode.connectionsCount || 0) + 1;
      const tNode = nodesMap.get(targetId);
      if (tNode) tNode.connectionsCount = (tNode.connectionsCount || 0) + 1;
    }
  };

  // 5. Connect ENDPOINTS to CONSUMER FUNCTIONS
  for (const epNode of endpointNodes) {
    // Check which function encloses or references this endpoint
    let matchedFn = allFunctions.find(
      fn => fn.file === epNode.file && epNode.line >= fn.startLine && epNode.line <= fn.endLine
    );

    if (!matchedFn) {
      // Look for function body that contains endpoint path string
      matchedFn = allFunctions.find(fn => fn.file === epNode.file && fn.body.includes(epNode.label));
    }

    if (!matchedFn) {
      // Look across any file for a consumer calling this path
      matchedFn = allFunctions.find(fn => fn.body.includes(epNode.label));
    }

    if (matchedFn) {
      addLink(epNode.id, matchedFn.id, 'ENDPOINT_TO_CONSUMER', false, epNode.file, 'HTTP Request');
    }
  }

  // 6. Connect CONSUMER FUNCTIONS to DANGEROUS SINKS
  for (const sinkNode of sinkNodes) {
    // Find the enclosing function for this sink
    let matchedFn = allFunctions.find(
      fn => fn.file === sinkNode.file && sinkNode.line >= fn.startLine && sinkNode.line <= fn.endLine
    );

    if (!matchedFn) {
      // Find function that mentions this sink call
      matchedFn = allFunctions.find(
        fn => fn.file === sinkNode.file && sinkNode.snippet && fn.body.includes(sinkNode.snippet)
      );
    }

    if (matchedFn) {
      addLink(matchedFn.id, sinkNode.id, 'CONSUMER_TO_SINK', false, sinkNode.file, 'Sink Delivery');
    } else {
      // Module-level scope node for sinks outside functions
      const moduleScopeId = `mod-scope-${sinkNode.file}`;
      if (!nodesMap.has(moduleScopeId)) {
        const modNode: DataFlowNode = {
          id: moduleScopeId,
          type: 'CONSUMER',
          label: `[Global] ${sinkNode.file.split('/').pop()}`,
          sublabel: 'Escopo de Módulo',
          file: sinkNode.file,
          line: 1,
          description: `Escopo global do arquivo ${sinkNode.file}.`,
          tainted: false,
          connectionsCount: 0
        };
        nodesMap.set(moduleScopeId, modNode);
      }
      addLink(moduleScopeId, sinkNode.id, 'CONSUMER_TO_SINK', false, sinkNode.file, 'Global Invocation');
    }
  }

  // 7. Connect Inter-Function calls (e.g. renderUserProfile calls fetchPortalMetadata)
  // Bounded check: never compare 1-2 char names, max 40 links to prevent dense graph explosions
  const maxInterLinks = 40;
  let interLinksCreated = 0;
  for (const fnA of allFunctions) {
    if (interLinksCreated >= maxInterLinks) break;
    for (const fnB of allFunctions) {
      if (interLinksCreated >= maxInterLinks) break;
      if (fnA.id !== fnB.id && fnA.file === fnB.file) {
        if (fnB.name && fnB.name.length >= 3 && fnA.calls.includes(fnB.name)) {
          addLink(fnB.id, fnA.id, 'CONSUMER_TO_SINK', false, fnA.file, 'Data Invocation');
          interLinksCreated++;
        }
      }
    }
  }

  // 8. Taint Analysis: Propagate taint from Endpoints to Sinks and track tainted variables
  const extractTaintedVariable = (sinkNode: DataFlowNode): { variableName: string; sourceField: string } => {
    const snippet = sinkNode.snippet || '';

    // eval(payload.code) or eval(code)
    const evalMatch = /eval\s*\(\s*([a-zA-Z0-9_$.]+)/.exec(snippet);
    if (evalMatch && evalMatch[1]) {
      return { variableName: evalMatch[1], sourceField: 'req.body.code' };
    }

    // innerHTML = metadata.bioHtml or elem.innerHTML = val
    const innerHtmlMatch = /innerHTML\s*=\s*([a-zA-Z0-9_$.]+)/.exec(snippet);
    if (innerHtmlMatch && innerHtmlMatch[1]) {
      return { variableName: innerHtmlMatch[1], sourceField: 'res.json().bioHtml' };
    }

    // document.write(x)
    const docWriteMatch = /document\.write(?:ln)?\s*\(\s*([a-zA-Z0-9_$.]+)/.exec(snippet);
    if (docWriteMatch && docWriteMatch[1]) {
      return { variableName: docWriteMatch[1], sourceField: 'req.query.q' };
    }

    // localStorage.setItem("session_token", metadata.token)
    const storageMatch = /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`][^'"`]+['"`]\s*,\s*([a-zA-Z0-9_$.]+)/.exec(snippet);
    if (storageMatch && storageMatch[1]) {
      return { variableName: storageMatch[1], sourceField: 'res.json().token' };
    }

    // window.postMessage({ session: payload.token }, "*")
    const postMsgMatch = /postMessage\s*\(\s*\{[^}]*:\s*([a-zA-Z0-9_$.]+)/.exec(snippet);
    if (postMsgMatch && postMsgMatch[1]) {
      return { variableName: postMsgMatch[1], sourceField: 'req.body.token' };
    }

    // Function(..., code)
    const fnMatch = /Function\s*\([^)]*,\s*([a-zA-Z0-9_$.]+)\s*\)/.exec(snippet);
    if (fnMatch && fnMatch[1]) {
      return { variableName: fnMatch[1], sourceField: 'req.body.script' };
    }

    // Heuristics by sink type
    if (sinkNode.sinkType === 'EVAL') return { variableName: 'payload.code', sourceField: 'req.body.code' };
    if (sinkNode.sinkType === 'INNER_HTML') return { variableName: 'metadata.bioHtml', sourceField: 'res.data.bioHtml' };
    if (sinkNode.sinkType === 'INSECURE_STORAGE') return { variableName: 'metadata.token', sourceField: 'res.data.token' };
    if (sinkNode.sinkType === 'POST_MESSAGE') return { variableName: 'payload.token', sourceField: 'payload.token' };
    if (sinkNode.sinkType === 'DOCUMENT_WRITE') return { variableName: 'searchQuery', sourceField: 'req.query.search' };
    return { variableName: 'untrustedInput', sourceField: 'req.body' };
  };

  const adjacency: Map<string, string[]> = new Map();
  const linkByEndpoints: Map<string, DataFlowLink> = new Map();
  for (const link of links) {
    const s = typeof link.source === 'string' ? link.source : (link.source as DataFlowNode).id;
    const t = typeof link.target === 'string' ? link.target : (link.target as DataFlowNode).id;
    if (!adjacency.has(s)) adjacency.set(s, []);
    adjacency.get(s)!.push(t);
    linkByEndpoints.set(`${s}__TO__${t}`, link);
  }

  const reachableFromEndpoint: Set<string> = new Set();
  const taintedPathLinks: Set<string> = new Set();
  const taintFlows: TaintVariableFlow[] = [];
  const registeredFlowKeys = new Set<string>();

  // Limit BFS breadth and depth to guarantee instant execution
  const MAX_TAINT_FLOWS = 20;
  const MAX_BFS_DEPTH = 5;

  for (const epNode of endpointNodes) {
    if (taintFlows.length >= MAX_TAINT_FLOWS) break;

    const visitedInThisBfs: Set<string> = new Set();
    const queue: Array<{ current: string; path: string[] }> = [{ current: epNode.id, path: [epNode.id] }];

    while (queue.length > 0 && queue.length < 80) {
      if (taintFlows.length >= MAX_TAINT_FLOWS) break;
      const { current, path } = queue.shift()!;
      reachableFromEndpoint.add(current);

      if (path.length >= MAX_BFS_DEPTH) continue;

      const targetNeighbors = adjacency.get(current) || [];
      for (const next of targetNeighbors) {
        if (!visitedInThisBfs.has(next)) {
          visitedInThisBfs.add(next);
          const newPath = [...path, next];
          queue.push({ current: next, path: newPath });

          // If next is a sink, the entire path is a Tainted Flow!
          const nextNode = nodesMap.get(next);
          if (nextNode && nextNode.type === 'SINK') {
            const { variableName, sourceField } = extractTaintedVariable(nextNode);
            const pathLinkIds: string[] = [];

            for (let i = 0; i < newPath.length - 1; i++) {
              const edgeKey = `${newPath[i]}__TO__${newPath[i + 1]}`;
              taintedPathLinks.add(edgeKey);
              pathLinkIds.push(edgeKey);

              const linkObj = linkByEndpoints.get(edgeKey);
              if (linkObj) {
                linkObj.isTainted = true;
                linkObj.taintedVariable = variableName;
                if (!linkObj.taintedVariableList) linkObj.taintedVariableList = [];
                if (!linkObj.taintedVariableList.includes(variableName)) {
                  linkObj.taintedVariableList.push(variableName);
                }
              }

              const n = nodesMap.get(newPath[i]);
              if (n) {
                n.tainted = true;
                if (!n.taintedVariables) n.taintedVariables = [];
                if (!n.taintedVariables.includes(variableName)) {
                  n.taintedVariables.push(variableName);
                }
                n.taintRole = n.type === 'ENDPOINT' ? 'SOURCE' : 'PROPAGATOR';
              }
            }

            nextNode.tainted = true;
            if (!nextNode.taintedVariables) nextNode.taintedVariables = [];
            if (!nextNode.taintedVariables.includes(variableName)) {
              nextNode.taintedVariables.push(variableName);
            }
            nextNode.taintRole = 'SINK';

            // Register distinct TaintVariableFlow
            const flowKey = `${epNode.id}__${variableName}__${nextNode.id}`;
            if (!registeredFlowKeys.has(flowKey)) {
              registeredFlowKeys.add(flowKey);

              const intermediates = newPath.slice(1, -1);
              const intermediateLabels = intermediates
                .map(id => nodesMap.get(id)?.label.replace('()', '') || id)
                .filter(Boolean);

              const transformSummary = intermediateLabels.length > 0
                ? `Ingressado via ${epNode.label} (${sourceField}) ➔ Propagado em ${intermediateLabels.join(' ➔ ')} ➔ Consumido sem sanitização em ${nextNode.label}`
                : `Ingressado via ${epNode.label} ➔ Consumido diretamente em ${nextNode.label}`;

              const taxonomy = SINK_TAXONOMY[nextNode.sinkType as DangerousSinkFinding['sinkType']] || {
                cwe: nextNode.cwe || { id: 'CWE-20', name: 'Improper Input Validation' },
                riskCategory: nextNode.riskCategory || 'Dangerous Sink Execution',
                threatDescription: nextNode.description || 'Execução insegura de variável não sanitizada.'
              };

              taintFlows.push({
                id: `taint-flow-${taintFlows.length + 1}`,
                variableName,
                sourceNodeId: epNode.id,
                sourceLabel: epNode.label,
                sourceParamOrField: sourceField,
                intermediateNodeIds: intermediates,
                sinkNodeId: nextNode.id,
                sinkLabel: nextNode.label,
                sinkType: nextNode.sinkType || 'SINK',
                pathNodeIds: newPath,
                pathLinkIds,
                severity: nextNode.severity || 'CRITICAL',
                riskCategory: taxonomy.riskCategory,
                cwe: taxonomy.cwe,
                description: `A variável "${variableName}" é recebida do endpoint não confiável ${epNode.label} e transita sem validação até o sink crítico ${nextNode.label}.`,
                variableTransformSummary: transformSummary
              });
            }
          }
        }
      }
    }
  }

  // Update all links marked in tainted paths
  let totalTaintFlows = 0;
  for (const link of links) {
    if (taintedPathLinks.has(link.id)) {
      link.isTainted = true;
      totalTaintFlows++;
    }
  }

  // If a sink is directly adjacent to a tainted consumer or endpoint, ensure it's marked
  for (const sinkNode of sinkNodes) {
    if (sinkNode.tainted) {
      sinkNode.severity = 'CRITICAL';
    }
  }

  const finalNodes = Array.from(nodesMap.values());

  // Metrics
  const criticalSinksCount = sinkNodes.filter(s => s.severity === 'CRITICAL' || s.tainted).length;

    return {
      nodes: finalNodes,
      links,
      taintFlows,
      metrics: {
        totalEndpoints: endpointNodes.length,
        totalConsumers: consumerNodes.length,
        totalSinks: sinkNodes.length,
        totalTaintFlows: taintFlows.length > 0 ? taintFlows.length : totalTaintFlows,
        criticalSinksCount,
        filesAnalyzed: activeFiles.length
      }
    };
  } catch (err) {
    console.warn('Safe fallback in buildDataFlowGraph:', err);
    return {
      nodes: [],
      links: [],
      taintFlows: [],
      metrics: {
        totalEndpoints: apiEndpoints.length,
        totalConsumers: 0,
        totalSinks: dangerousSinks.length,
        totalTaintFlows: 0,
        criticalSinksCount: dangerousSinks.filter(s => s.severity === 'CRITICAL').length,
        filesAnalyzed: files.length
      }
    };
  }
}
