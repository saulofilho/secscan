import {
  ScannedFile,
  ApiEndpointFinding,
  DangerousSinkFinding,
  DataFlowNode,
  DataFlowLink,
  DataFlowGraphData,
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

/**
 * Extracts functions from source code with line ranges and body content
 */
export function extractFunctionsFromSource(file: ScannedFile): ExtractedFunction[] {
  const content = file.content;
  if (!content) return [];

  const lines = content.split('\n');
  const functions: ExtractedFunction[] = [];

  // Patterns for function declarations and methods
  const FUNCTION_HEADER_PATTERNS = [
    // async function name(...) or function name(...)
    /(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)/g,
    // const/let/var name = async (...) => or name = (...) =>
    /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|[a-zA-Z0-9_$]+)\s*=>/g,
    // const/let/var name = async function(...)
    /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?function\s*\(([^)]*)\)/g,
    // static async methodName(...) or async methodName(...) or methodName(...) inside class
    /(?:static\s+)?(?:async\s+)?([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{/g,
    // router.post('/path', async (req, res) => ...)
    /(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/g
  ];

  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i];

    // Check for route handler: router.post('/path', ...)
    const routeMatch = /(?:router|app)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/i.exec(lineText);
    if (routeMatch) {
      const method = routeMatch[1].toUpperCase();
      const routePath = routeMatch[2];
      const fnName = `RouteHandler: ${method} ${routePath}`;
      const startLine = i + 1;
      const { endLine, body } = estimateFunctionBlock(lines, i);

      functions.push({
        id: `fn-${file.path}-${startLine}-${functions.length}`,
        name: fnName,
        file: file.path,
        startLine,
        endLine,
        snippet: lineText.trim(),
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
        // Skip common keywords mistakenly captured
        if (['if', 'for', 'while', 'switch', 'catch', 'constructor'].includes(fnName)) {
          continue;
        }

        const startLine = i + 1;
        // Avoid duplicate start line
        if (functions.some(f => f.file === file.path && f.startLine === startLine)) {
          continue;
        }

        const { endLine, body } = estimateFunctionBlock(lines, i);

        functions.push({
          id: `fn-${file.path}-${startLine}-${fnName}`,
          name: fnName,
          file: file.path,
          startLine,
          endLine,
          snippet: lineText.trim(),
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
 * Estimates the closing line of a function block by counting braces
 */
function estimateFunctionBlock(lines: string[], startIdx: number): { endLine: number; body: string } {
  let openBraces = 0;
  let hasOpened = false;
  let endIdx = startIdx;

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i];
    for (const ch of line) {
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

    // Safeguard: Max function size 300 lines
    if (i - startIdx > 300) {
      endIdx = i;
      break;
    }
  }

  const body = lines.slice(startIdx, endIdx + 1).join('\n');
  return { endLine: endIdx + 1, body };
}

/**
 * Extracts calls to other functions or API clients from function body
 */
function extractCallsFromBody(body: string): string[] {
  const calls: Set<string> = new Set();
  const callRegex = /\b([a-zA-Z0-9_$]{2,40})\s*\(/g;
  let m: RegExpExecArray | null;

  while ((m = callRegex.exec(body)) !== null) {
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
  for (const fnA of allFunctions) {
    for (const fnB of allFunctions) {
      if (fnA.id !== fnB.id && fnA.file === fnB.file) {
        if (fnA.calls.includes(fnB.name) || fnA.body.includes(fnB.name)) {
          addLink(fnB.id, fnA.id, 'CONSUMER_TO_SINK', false, fnA.file, 'Data Invocation');
        }
      }
    }
  }

  // 8. Taint Analysis: Propagate taint from Endpoints to Sinks
  // A sink is tainted if there exists a directed path from an Endpoint to it
  const adjacency: Map<string, string[]> = new Map();
  for (const link of links) {
    const s = typeof link.source === 'string' ? link.source : (link.source as DataFlowNode).id;
    const t = typeof link.target === 'string' ? link.target : (link.target as DataFlowNode).id;
    if (!adjacency.has(s)) adjacency.set(s, []);
    adjacency.get(s)!.push(t);
  }

  const reachableFromEndpoint: Set<string> = new Set();
  const taintedPaths: Set<string> = new Set();

  for (const epNode of endpointNodes) {
    const visitedInThisBfs: Set<string> = new Set();
    const queue: Array<{ current: string; path: string[] }> = [{ current: epNode.id, path: [epNode.id] }];

    while (queue.length > 0) {
      const { current, path } = queue.shift()!;
      reachableFromEndpoint.add(current);

      const targetNeighbors = adjacency.get(current) || [];
      for (const next of targetNeighbors) {
        if (!visitedInThisBfs.has(next)) {
          visitedInThisBfs.add(next);
          const newPath = [...path, next];
          queue.push({ current: next, path: newPath });

          // If next is a sink, the entire path is a Tainted Flow!
          const nextNode = nodesMap.get(next);
          if (nextNode && nextNode.type === 'SINK') {
            for (let i = 0; i < newPath.length - 1; i++) {
              taintedPaths.add(`${newPath[i]}__TO__${newPath[i + 1]}`);
              const n = nodesMap.get(newPath[i]);
              if (n) n.tainted = true;
            }
            nextNode.tainted = true;
          }
        }
      }
    }
  }

  // Update links with tainted status
  let totalTaintFlows = 0;
  for (const link of links) {
    if (taintedPaths.has(link.id)) {
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
    metrics: {
      totalEndpoints: endpointNodes.length,
      totalConsumers: consumerNodes.length,
      totalSinks: sinkNodes.length,
      totalTaintFlows,
      criticalSinksCount,
      filesAnalyzed: activeFiles.length
    }
  };
}
