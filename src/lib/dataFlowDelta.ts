import {
  DataFlowNode,
  DataFlowLink,
  DataFlowGraphData,
  TaintVariableFlow,
  DataFlowDeltaAnalysis,
  DataFlowVulnerabilityDelta
} from '../types';

/**
 * Creates a unique deterministic key for a node across scans
 */
function getNodeFingerprint(node: DataFlowNode): string {
  // Try ID first if it's semantic, otherwise type + file + line + label
  return `${node.type}::${node.file}::${node.line}::${node.label.trim()}`;
}

/**
 * Creates a unique deterministic key for a link
 */
function getLinkFingerprint(link: DataFlowLink): string {
  const s = typeof link.source === 'string' ? link.source : (link.source as DataFlowNode).id;
  const t = typeof link.target === 'string' ? link.target : (link.target as DataFlowNode).id;
  return `${s}__-->__${t}`;
}

/**
 * Creates a unique deterministic key for a taint variable flow
 */
function getTaintFlowFingerprint(flow: TaintVariableFlow): string {
  return `${flow.sourceLabel.trim()}__$${flow.variableName.trim()}__${flow.sinkLabel.trim()}`;
}

/**
 * Calculates the delta diff between a previous DataFlowGraphData and the current DataFlowGraphData.
 * Highlights new vulnerabilities, newly tainted nodes/links, remediated flaws, and added/removed components.
 */
export function calculateDataFlowDelta(
  previousGraph: DataFlowGraphData | null | undefined,
  currentGraph: DataFlowGraphData,
  baselineName: string = 'Versão Anterior'
): DataFlowDeltaAnalysis {
  const currentTimestamp = new Date().toLocaleTimeString();

  // If no previous analysis exists, treat all tainted items as current baseline
  if (!previousGraph || !previousGraph.nodes || previousGraph.nodes.length === 0) {
    const nodeDeltaMap: DataFlowDeltaAnalysis['nodeDeltaMap'] = {};
    currentGraph.nodes.forEach(n => {
      nodeDeltaMap[n.id] = {
        status: 'UNCHANGED',
        isNewlyTainted: false,
        currentTainted: n.tainted,
        changeDescription: 'Linha de base inicial estabelecida'
      };
    });

    const linkDeltaMap: DataFlowDeltaAnalysis['linkDeltaMap'] = {};
    currentGraph.links.forEach(l => {
      linkDeltaMap[l.id] = {
        status: 'UNCHANGED',
        isNewlyTainted: false
      };
    });

    const currentFlows = currentGraph.taintFlows || [];
    const persistentVulnerabilities: DataFlowVulnerabilityDelta[] = currentFlows.map((flow, idx) => ({
      id: `delta-persistent-${idx}`,
      type: 'PERSISTENT_VULNERABILITY',
      flow,
      severity: flow.severity,
      changeReason: 'Presente na análise inicial',
      introducedInFile: flow.pathNodeIds[0] ? (currentGraph.nodes.find(n => n.id === flow.pathNodeIds[0])?.file || '') : '',
      variableName: flow.variableName,
      sourceLabel: flow.sourceLabel,
      sinkLabel: flow.sinkLabel,
      riskCategory: flow.riskCategory,
      cwe: flow.cwe,
      remediationAdvice: flow.sinkType === 'EVAL'
        ? 'Substituir eval() por analisador estático JSON.parse ou arquitetura declarativa.'
        : flow.sinkType === 'INNER_HTML'
        ? 'Sanitizar HTML via DOMPurify.sanitize() ou usar textContent.'
        : flow.sinkType === 'INSECURE_STORAGE'
        ? 'Armazenar segredos em cookies HttpOnly/SameSite ou sessão criptografada.'
        : 'Validar dados na borda e aplicar sanitização antes da chamada do sink.'
    }));

    return {
      hasPreviousAnalysis: false,
      baselineName: 'Nenhuma (Primeira Análise)',
      currentTimestamp,
      nodeDeltaMap,
      linkDeltaMap,
      vulnerabilityDeltas: persistentVulnerabilities,
      newVulnerabilities: [],
      resolvedVulnerabilities: [],
      persistentVulnerabilities,
      metrics: {
        newVulnerabilitiesCount: 0,
        resolvedVulnerabilitiesCount: 0,
        netVulnerabilityDelta: 0,
        newNodesCount: 0,
        removedNodesCount: 0,
        modifiedNodesCount: 0,
        newlyTaintedNodesCount: 0,
        newLinksCount: 0,
        riskStatus: persistentVulnerabilities.length > 0 ? 'REGRESSION_WARNING' : 'NEUTRAL'
      },
      removedNodes: [],
      removedLinks: []
    };
  }

  // Build lookup maps for previous graph
  const prevNodesById = new Map<string, DataFlowNode>(previousGraph.nodes.map(n => [n.id, n]));
  const prevNodesByFp = new Map<string, DataFlowNode>(previousGraph.nodes.map(n => [getNodeFingerprint(n), n]));

  const prevLinksById = new Map<string, DataFlowLink>(previousGraph.links.map(l => [l.id, l]));
  const prevLinksByFp = new Map<string, DataFlowLink>(previousGraph.links.map(l => [getLinkFingerprint(l), l]));

  const prevFlowsByFp = new Map<string, TaintVariableFlow>(
    (previousGraph.taintFlows || []).map(f => [getTaintFlowFingerprint(f), f])
  );

  const nodeDeltaMap: DataFlowDeltaAnalysis['nodeDeltaMap'] = {};
  let newNodesCount = 0;
  let modifiedNodesCount = 0;
  let newlyTaintedNodesCount = 0;

  // Process current nodes
  currentGraph.nodes.forEach(currNode => {
    const prevMatch = prevNodesById.get(currNode.id) || prevNodesByFp.get(getNodeFingerprint(currNode));

    if (!prevMatch) {
      // Node is newly introduced in the current scan
      newNodesCount++;
      const isNewlyTainted = Boolean(currNode.tainted);
      if (isNewlyTainted) newlyTaintedNodesCount++;

      nodeDeltaMap[currNode.id] = {
        status: 'NEW',
        isNewlyTainted,
        previousTainted: false,
        currentTainted: currNode.tainted,
        newlyAddedVariables: currNode.taintedVariables || [],
        changeDescription: `Novo nó introduzido nas alterações recentes (${currNode.label})`
      };
    } else {
      // Node existed in previous scan - check for mutations
      const becameTainted = !prevMatch.tainted && Boolean(currNode.tainted);
      const becameClean = Boolean(prevMatch.tainted) && !currNode.tainted;
      const prevVars = new Set(prevMatch.taintedVariables || []);
      const newVars = (currNode.taintedVariables || []).filter(v => !prevVars.has(v));

      if (becameTainted) {
        newlyTaintedNodesCount++;
        modifiedNodesCount++;
        nodeDeltaMap[currNode.id] = {
          status: 'MODIFIED',
          isNewlyTainted: true,
          previousTainted: false,
          currentTainted: true,
          newlyAddedVariables: currNode.taintedVariables || [],
          changeDescription: `Regressão: Este nó era seguro na versão anterior, mas tornou-se tainted agora.`
        };
      } else if (becameClean) {
        modifiedNodesCount++;
        nodeDeltaMap[currNode.id] = {
          status: 'MODIFIED',
          isNewlyTainted: false,
          previousTainted: true,
          currentTainted: false,
          changeDescription: `Melhoria: Taint removido/sanitizado com sucesso nas alterações recentes.`
        };
      } else if (newVars.length > 0) {
        modifiedNodesCount++;
        nodeDeltaMap[currNode.id] = {
          status: 'MODIFIED',
          isNewlyTainted: true,
          previousTainted: prevMatch.tainted,
          currentTainted: currNode.tainted,
          newlyAddedVariables: newVars,
          changeDescription: `Novas variáveis não confiáveis propagadas: ${newVars.map(v => `$${v}`).join(', ')}`
        };
      } else {
        nodeDeltaMap[currNode.id] = {
          status: 'UNCHANGED',
          isNewlyTainted: false,
          previousTainted: prevMatch.tainted,
          currentTainted: currNode.tainted,
          changeDescription: 'Estrutura e taint inalterados'
        };
      }
    }
  });

  // Check for removed nodes (present in previous, missing in current)
  const currentFpSet = new Set(currentGraph.nodes.map(n => getNodeFingerprint(n)));
  const currentIdSet = new Set(currentGraph.nodes.map(n => n.id));
  const removedNodes: DataFlowNode[] = [];

  previousGraph.nodes.forEach(prevNode => {
    if (!currentIdSet.has(prevNode.id) && !currentFpSet.has(getNodeFingerprint(prevNode))) {
      removedNodes.push({
        ...prevNode,
        id: `removed-${prevNode.id}`,
        label: `${prevNode.label} (Removido)`,
        deltaStatus: 'REMOVED',
        isGhostRemoved: true,
        deltaReason: 'Removido ou refatorado no código recente'
      });
    }
  });

  // Process links
  const linkDeltaMap: DataFlowDeltaAnalysis['linkDeltaMap'] = {};
  let newLinksCount = 0;

  currentGraph.links.forEach(currLink => {
    const prevLink = prevLinksById.get(currLink.id) || prevLinksByFp.get(getLinkFingerprint(currLink));

    if (!prevLink) {
      newLinksCount++;
      linkDeltaMap[currLink.id] = {
        status: 'NEW',
        isNewlyTainted: Boolean(currLink.isTainted),
        changeDescription: 'Nova conexão de fluxo estabelecida'
      };
    } else if (!prevLink.isTainted && currLink.isTainted) {
      linkDeltaMap[currLink.id] = {
        status: 'NEWLY_TAINTED',
        isNewlyTainted: true,
        changeDescription: 'Fluxo tornou-se propagador de dados contaminados'
      };
    } else if (prevLink.isTainted && !currLink.isTainted) {
      linkDeltaMap[currLink.id] = {
        status: 'REMEDIATED',
        isNewlyTainted: false,
        changeDescription: 'Fluxo sanitizado'
      };
    } else {
      linkDeltaMap[currLink.id] = {
        status: 'UNCHANGED',
        isNewlyTainted: false
      };
    }
  });

  // Process Taint Variable Flows Diff (End-to-End Vulnerabilities)
  const currentFlows = currentGraph.taintFlows || [];
  const currentFlowFpSet = new Set<string>();

  const newVulnerabilities: DataFlowVulnerabilityDelta[] = [];
  const persistentVulnerabilities: DataFlowVulnerabilityDelta[] = [];

  currentFlows.forEach((flow, idx) => {
    const fp = getTaintFlowFingerprint(flow);
    currentFlowFpSet.add(fp);

    const prevFlow = prevFlowsByFp.get(fp);

    if (!prevFlow) {
      // Newly introduced taint flow!
      const sinkNode = currentGraph.nodes.find(n => n.id === flow.sinkNodeId);
      const sourceNode = currentGraph.nodes.find(n => n.id === flow.sourceNodeId);

      newVulnerabilities.push({
        id: `delta-new-${idx}`,
        type: 'NEW_VULNERABILITY',
        flow,
        severity: flow.severity,
        changeReason: `Nova vulnerabilidade introduzida: rota "${flow.sourceLabel}" passa a variável "$${flow.variableName}" para "${flow.sinkLabel}" sem sanitização.`,
        introducedInFile: sinkNode?.file || sourceNode?.file || 'src/index.ts',
        introducedAtLine: sinkNode?.line || sourceNode?.line,
        variableName: flow.variableName,
        sourceLabel: flow.sourceLabel,
        sinkLabel: flow.sinkLabel,
        riskCategory: flow.riskCategory,
        cwe: flow.cwe,
        remediationAdvice: flow.sinkType === 'EVAL'
          ? 'Substituir eval() por analisador seguro ou aplicar sandbox estrita.'
          : flow.sinkType === 'INNER_HTML'
          ? 'Utilizar DOMPurify.sanitize(input) ou element.textContent para neutralizar scripts.'
          : flow.sinkType === 'INSECURE_STORAGE'
          ? 'Não persistir tokens não criptografados em localStorage. Migrar para cookies HttpOnly.'
          : flow.sinkType === 'POST_MESSAGE'
          ? 'Especificar targetOrigin explícito ao invés de "*".'
          : 'Aplicar sanitização e validação com schemas (ex: Zod/Joi) antes de repassar para o sink.',
        codeSnippetPreview: sinkNode?.snippet || sourceNode?.snippet
      });
    } else {
      persistentVulnerabilities.push({
        id: `delta-persist-${idx}`,
        type: 'PERSISTENT_VULNERABILITY',
        flow,
        severity: flow.severity,
        changeReason: 'Vulnerabilidade pré-existente ainda não corrigida',
        introducedInFile: currentGraph.nodes.find(n => n.id === flow.sinkNodeId)?.file || '',
        variableName: flow.variableName,
        sourceLabel: flow.sourceLabel,
        sinkLabel: flow.sinkLabel,
        riskCategory: flow.riskCategory,
        cwe: flow.cwe,
        remediationAdvice: 'Aplicar sanitização no ponto de consumo.'
      });
    }
  });

  // Check for resolved vulnerabilities (present in prevFlows, missing in current)
  const resolvedVulnerabilities: DataFlowVulnerabilityDelta[] = [];
  (previousGraph.taintFlows || []).forEach((prevFlow, idx) => {
    const fp = getTaintFlowFingerprint(prevFlow);
    if (!currentFlowFpSet.has(fp)) {
      resolvedVulnerabilities.push({
        id: `delta-resolved-${idx}`,
        type: 'RESOLVED_VULNERABILITY',
        flow: prevFlow,
        severity: prevFlow.severity,
        changeReason: `Vulnerabilidade sanada: o fluxo da variável "$${prevFlow.variableName}" para "${prevFlow.sinkLabel}" foi corrigido ou removido.`,
        introducedInFile: prevFlow.sourceLabel,
        variableName: prevFlow.variableName,
        sourceLabel: prevFlow.sourceLabel,
        sinkLabel: prevFlow.sinkLabel,
        riskCategory: prevFlow.riskCategory,
        cwe: prevFlow.cwe,
        remediationAdvice: 'Correção verificada. Mantenha os testes de regressão ativos.'
      });
    }
  });

  const newVulnerabilitiesCount = newVulnerabilities.length;
  const resolvedVulnerabilitiesCount = resolvedVulnerabilities.length;
  const netVulnerabilityDelta = newVulnerabilitiesCount - resolvedVulnerabilitiesCount;

  let riskStatus: DataFlowDeltaAnalysis['metrics']['riskStatus'] = 'NEUTRAL';
  if (newVulnerabilitiesCount > 0) {
    const hasCrit = newVulnerabilities.some(v => v.severity === 'CRITICAL');
    riskStatus = hasCrit ? 'REGRESSION_CRITICAL' : 'REGRESSION_WARNING';
  } else if (resolvedVulnerabilitiesCount > 0) {
    riskStatus = 'IMPROVED';
  }

  return {
    hasPreviousAnalysis: true,
    baselineName,
    previousTimestamp: 'Versão Anterior',
    currentTimestamp,
    nodeDeltaMap,
    linkDeltaMap,
    vulnerabilityDeltas: [...newVulnerabilities, ...resolvedVulnerabilities, ...persistentVulnerabilities],
    newVulnerabilities,
    resolvedVulnerabilities,
    persistentVulnerabilities,
    metrics: {
      newVulnerabilitiesCount,
      resolvedVulnerabilitiesCount,
      netVulnerabilityDelta,
      newNodesCount,
      removedNodesCount: removedNodes.length,
      modifiedNodesCount,
      newlyTaintedNodesCount,
      newLinksCount,
      riskStatus
    },
    removedNodes,
    removedLinks: []
  };
}

/**
 * Creates a synthetic baseline scenario for instant demo/testing of delta calculations
 */
export function generateSimulatedPreviousGraph(
  currentGraph: DataFlowGraphData,
  scenario: 'CLEAN_BASELINE' | 'PARTIAL_TAINT' | 'NEW_SINK_INTRODUCED' = 'PARTIAL_TAINT'
): DataFlowGraphData {
  if (!currentGraph || currentGraph.nodes.length === 0) {
    return {
      nodes: [],
      links: [],
      metrics: {
        totalEndpoints: 0,
        totalConsumers: 0,
        totalSinks: 0,
        totalTaintFlows: 0,
        criticalSinksCount: 0,
        filesAnalyzed: 0
      }
    };
  }

  if (scenario === 'CLEAN_BASELINE') {
    // In clean baseline, endpoints and consumers exist, but sinks are not tainted or don't receive input
    const cleanNodes = currentGraph.nodes
      .filter(n => n.type !== 'SINK' || !n.tainted)
      .map(n => ({
        ...n,
        tainted: false,
        taintedVariables: [],
        severity: undefined
      }));

    const cleanNodeIds = new Set(cleanNodes.map(n => n.id));
    const cleanLinks = currentGraph.links
      .filter(l => {
        const s = typeof l.source === 'string' ? l.source : (l.source as DataFlowNode).id;
        const t = typeof l.target === 'string' ? l.target : (l.target as DataFlowNode).id;
        return cleanNodeIds.has(s) && cleanNodeIds.has(t);
      })
      .map(l => ({
        ...l,
        isTainted: false,
        taintedVariable: undefined,
        taintedVariableList: []
      }));

    return {
      nodes: cleanNodes,
      links: cleanLinks,
      taintFlows: [],
      metrics: {
        totalEndpoints: cleanNodes.filter(n => n.type === 'ENDPOINT').length,
        totalConsumers: cleanNodes.filter(n => n.type === 'CONSUMER').length,
        totalSinks: cleanNodes.filter(n => n.type === 'SINK').length,
        totalTaintFlows: 0,
        criticalSinksCount: 0,
        filesAnalyzed: currentGraph.metrics.filesAnalyzed
      }
    };
  }

  // PARTIAL_TAINT scenario:
  // Keeps only the first taint flow (if any), removing the newer ones so delta shows 1 or 2 new vulnerabilities!
  const currentFlows = currentGraph.taintFlows || [];
  const keptFlow = currentFlows.length > 1 ? [currentFlows[0]] : [];
  const keptFlowSinkIds = new Set(keptFlow.map(f => f.sinkNodeId));
  const keptFlowPathNodeIds = new Set(keptFlow.flatMap(f => f.pathNodeIds));

  // The other sinks in current were either safe or newly introduced
  const prevNodes = currentGraph.nodes.map(n => {
    if (n.type === 'SINK' && !keptFlowSinkIds.has(n.id)) {
      return {
        ...n,
        tainted: false,
        taintedVariables: [],
        severity: (n.severity === 'CRITICAL' ? 'HIGH' : n.severity) as any
      };
    }
    if (n.type === 'CONSUMER' && !keptFlowPathNodeIds.has(n.id)) {
      return {
        ...n,
        tainted: false,
        taintedVariables: []
      };
    }
    return { ...n };
  });

  const prevLinks = currentGraph.links.map(l => {
    const s = typeof l.source === 'string' ? l.source : (l.source as DataFlowNode).id;
    const t = typeof l.target === 'string' ? l.target : (l.target as DataFlowNode).id;
    const isKept = keptFlowPathNodeIds.has(s) && keptFlowPathNodeIds.has(t);
    return {
      ...l,
      isTainted: isKept
    };
  });

  return {
    nodes: prevNodes,
    links: prevLinks,
    taintFlows: keptFlow,
    metrics: {
      totalEndpoints: prevNodes.filter(n => n.type === 'ENDPOINT').length,
      totalConsumers: prevNodes.filter(n => n.type === 'CONSUMER').length,
      totalSinks: prevNodes.filter(n => n.type === 'SINK').length,
      totalTaintFlows: keptFlow.length,
      criticalSinksCount: keptFlow.length,
      filesAnalyzed: currentGraph.metrics.filesAnalyzed
    }
  };
}
