import { ScannedFile, ScanFinding, SuggestedFixResult, SuggestedFixEnvConfig } from '../types';

export interface RemediationPatch {
  id: string;
  findingId: string;
  title: string;
  file: string;
  line: number;
  originalSnippet: string;
  replacementSnippet: string;
  unifiedDiff: string;
  explanation: string;
  category: 'SECRET_EXTRACTION' | 'INJECTION_PREVENTION' | 'DOM_SANITIZATION' | 'INFRA_HARDENING' | 'PARAMETRIZATION';
  status: 'PENDING' | 'APPLIED' | 'REVERTED';
  cwe: string;
  severity?: string;
  source: 'gemini' | 'rule_engine';
  model?: string;
  securePattern?: string;
  envConfig?: SuggestedFixEnvConfig;
  envSnippetNeeded?: string;
  securityChecklist?: string[];
  riskReductionPoints?: number;
  diff?: {
    removed: string[];
    added: string[];
  };
  previousFileContentSnapshot?: string;
}

export function generateRemediationPatchForFinding(finding: ScanFinding, files: ScannedFile[]): RemediationPatch | null {
  const targetFile = files.find(f => f.path === finding.file);
  if (!targetFile) return null;

  let replacement = '';
  let explanation = '';
  let category: RemediationPatch['category'] = 'SECRET_EXTRACTION';
  let envSnippetNeeded: string | undefined;
  let envConfig: SuggestedFixEnvConfig | undefined;
  let securePattern = 'Externalized Secrets Manager & Environment Variables';
  let cwe = 'CWE-798';

  const original = (finding.snippet || finding.matchedSecret || '').trim();

  // Pattern 1: Hardcoded Secret / Token in assignment
  if (finding.matchedSecret && (finding.snippet.includes('=') || finding.snippet.includes(':'))) {
    category = 'SECRET_EXTRACTION';
    cwe = 'CWE-798: Hardcoded Credentials';
    securePattern = 'Runtime Secrets Injection & Fail-Fast Guard';
    const envVarName = `SECRET_${(finding.ruleId || 'KEY').replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`;
    
    if (finding.snippet.includes('const ') || finding.snippet.includes('let ') || finding.snippet.includes('var ')) {
      replacement = finding.snippet.replace(/["'][^"']+["']/, `process.env.${envVarName} || ""`);
    } else if (finding.snippet.includes(':')) {
      replacement = finding.snippet.replace(/:\s*["'][^"']+["']/, `: process.env.${envVarName} || ""`);
    } else {
      replacement = `// REMEDIATED BY SECSCAN: Hardcoded key replaced with environment variable\nconst secureToken = process.env.${envVarName};\nif (!secureToken) throw new Error("${envVarName} obrigatória ausente no ambiente");`;
    }

    explanation = `Removeu o segredo em texto claro e parametrizou via variável de ambiente 'process.env.${envVarName}'.`;
    envSnippetNeeded = `${envVarName}=sua_chave_aqui_gerenciada_por_vault`;
    envConfig = {
      variableName: envVarName,
      exampleLine: `${envVarName}=sua_chave_ou_token_aqui`,
      instructions: `Adicione ${envVarName} no seu arquivo .env local e no cofre seguro do CI/CD.`
    };
  } 
  // Pattern 2: Dangerous eval execution
  else if (finding.snippet.includes('eval(')) {
    category = 'INJECTION_PREVENTION';
    cwe = 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code';
    securePattern = 'Safe JSON Parser & Deserialization Isolation';
    replacement = finding.snippet.replace(/eval\(([^)]+)\)/, 'JSON.parse($1)');
    explanation = 'Substituiu a execução insegura de código arbitrário eval() pelo parser seguro nativo JSON.parse().';
  } 
  // Pattern 3: Unsafe innerHTML
  else if (finding.snippet.includes('.innerHTML')) {
    category = 'DOM_SANITIZATION';
    cwe = 'CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)';
    securePattern = 'Context-Aware Output Sanitization (DOMPurify)';
    replacement = finding.snippet.replace(/(\w+)\.innerHTML\s*=\s*(.+);?/, '$1.innerHTML = DOMPurify.sanitize($2);');
    explanation = 'Aplicou a sanitização contextual do DOMPurify para neutralizar payloads de Cross-Site Scripting (XSS).';
  } 
  // Pattern 4: Wildcard postMessage
  else if (finding.snippet.includes('postMessage') && finding.snippet.includes('*')) {
    category = 'INJECTION_PREVENTION';
    cwe = 'CWE-345: Insufficient Verification of Data Authenticity';
    securePattern = 'Strict Window Origin Matching';
    replacement = finding.snippet.replace(/postMessage\(([^,]+),\s*["']\*["']\)/, 'postMessage($1, window.location.origin)');
    explanation = 'Restringiu o destino da mensagem da janela para window.location.origin, mitigando vazamento de tokens para iframes maliciosos.';
  } else {
    // Default fallback
    category = 'SECRET_EXTRACTION';
    cwe = 'CWE-798: Sensitive Hardcoded Data';
    securePattern = 'Environment Credentials Isolation';
    const fallbackVar = `APP_${(finding.ruleId || 'SECRET').toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;
    replacement = `// REMEDIATED BY SECSCAN: Secure environment retrieval\nprocess.env.${fallbackVar} || ""`;
    explanation = 'Isolamento de valor confidencial em cofre de credenciais e injeção de ambiente.';
    envConfig = {
      variableName: fallbackVar,
      exampleLine: `${fallbackVar}=placeholder_configurado_em_vault`,
      instructions: `Injete ${fallbackVar} no ambiente da aplicação.`
    };
  }

  const removedLines = [original];
  const addedLines = replacement.trim().split('\n');

  const unifiedDiff = `--- a/${finding.file}
+++ b/${finding.file}
@@ -${finding.line},1 +${finding.line},${addedLines.length} @@
-  ${original}
${addedLines.map(l => `+  ${l}`).join('\n')}`;

  const pts = finding.severity === 'CRITICAL' ? 25 : (finding.severity === 'HIGH' ? 15 : 8);

  return {
    id: `patch-${finding.id}`,
    findingId: finding.id,
    title: `Correção: ${finding.ruleName}`,
    file: finding.file,
    line: finding.line,
    originalSnippet: original,
    replacementSnippet: replacement.trim(),
    unifiedDiff,
    explanation,
    category,
    status: 'PENDING',
    cwe,
    severity: finding.severity,
    source: 'rule_engine',
    model: 'SecScan Deterministic AppSec Engine',
    securePattern,
    envConfig,
    envSnippetNeeded,
    riskReductionPoints: pts,
    diff: {
      removed: removedLines,
      added: addedLines
    },
    securityChecklist: [
      'Validar que a nova variável de ambiente está carregada em tempo de execução.',
      'Executar testes de unidade do componente afetado.',
      'Re-executar a varredura SAST para certificar redução do Risk Score.'
    ]
  };
}

/**
 * Converts an AI-generated SuggestedFixResult from Gemini into a standard RemediationPatch
 */
export function convertSuggestedFixToPatch(
  fixResult: SuggestedFixResult,
  finding: ScanFinding,
  targetFile: ScannedFile
): RemediationPatch {
  const original = (fixResult.beforeSnippet || finding.snippet || finding.matchedSecret || '').trim();
  const replacement = (fixResult.replacementSnippet || '').trim();

  const removedLines = fixResult.diff?.removed && fixResult.diff.removed.length > 0
    ? fixResult.diff.removed
    : [original];
  const addedLines = fixResult.diff?.added && fixResult.diff.added.length > 0
    ? fixResult.diff.added
    : replacement.split('\n');

  const unifiedDiff = `--- a/${finding.file}
+++ b/${finding.file}
@@ -${finding.line},${removedLines.length} +${finding.line},${addedLines.length} @@
${removedLines.map(l => `-  ${l}`).join('\n')}
${addedLines.map(l => `+  ${l}`).join('\n')}`;

  const pts = finding.severity === 'CRITICAL' ? 25 : (finding.severity === 'HIGH' ? 15 : 8);

  return {
    id: `patch-${finding.id}`,
    findingId: finding.id,
    title: `Correção IA (${fixResult.model || 'Gemini'}): ${finding.ruleName}`,
    file: finding.file,
    line: finding.line,
    originalSnippet: original,
    replacementSnippet: replacement,
    unifiedDiff,
    explanation: fixResult.explanation || `Correção segura sintetizada com o padrão ${fixResult.securePattern}.`,
    category: (finding.category?.includes('INJECTION') || finding.ruleName.toLowerCase().includes('eval')) ? 'INJECTION_PREVENTION' : 'SECRET_EXTRACTION',
    status: 'PENDING',
    cwe: fixResult.cweOwaspReference || 'CWE-798',
    severity: finding.severity,
    source: fixResult.source,
    model: fixResult.model,
    securePattern: fixResult.securePattern,
    envConfig: fixResult.envConfig,
    envSnippetNeeded: fixResult.envConfig?.exampleLine,
    securityChecklist: fixResult.securityChecklist,
    riskReductionPoints: pts,
    diff: {
      removed: removedLines,
      added: addedLines
    }
  };
}

/**
 * Applies a generated patch directly into the file's content in workspace memory
 */
export function applyPatchToFile(
  files: ScannedFile[],
  patch: RemediationPatch
): { updatedFiles: ScannedFile[]; success: boolean; message: string; previousSnapshot?: string } {
  const fileIndex = files.findIndex(f => f.path === patch.file || f.name === patch.file);
  if (fileIndex === -1) {
    return { updatedFiles: files, success: false, message: `Arquivo ${patch.file} não encontrado no workspace.` };
  }

  const targetFile = files[fileIndex];
  const previousSnapshot = targetFile.content;

  const originalSnippet = patch.originalSnippet.trim();
  const replacementSnippet = patch.replacementSnippet.trim();

  // Try exact replacement of originalSnippet
  if (originalSnippet && targetFile.content.includes(originalSnippet)) {
    const replacedContent = targetFile.content.replace(originalSnippet, replacementSnippet);
    const updatedFiles = [...files];
    updatedFiles[fileIndex] = {
      ...targetFile,
      content: replacedContent,
      size: new Blob([replacedContent]).size,
      lastModified: Date.now()
    };
    return {
      updatedFiles,
      success: true,
      message: `Patch aplicado com sucesso em ${targetFile.name}.`,
      previousSnapshot
    };
  }

  // Fallback to line matching
  const lines = targetFile.content.split('\n');
  const targetLineIdx = patch.line - 1;

  if (targetLineIdx >= 0 && targetLineIdx < lines.length) {
    // If the line has any overlap or matches
    lines[targetLineIdx] = replacementSnippet;
    const updatedContent = lines.join('\n');
    const updatedFiles = [...files];
    updatedFiles[fileIndex] = {
      ...targetFile,
      content: updatedContent,
      size: new Blob([updatedContent]).size,
      lastModified: Date.now()
    };
    return {
      updatedFiles,
      success: true,
      message: `Patch aplicado com sucesso na linha ${patch.line} de ${targetFile.name}.`,
      previousSnapshot
    };
  }

  return {
    updatedFiles: files,
    success: false,
    message: `Não foi possível alinhar o snippet no arquivo ${targetFile.name}. Verifique se o arquivo foi alterado.`
  };
}

/**
 * Reverts an applied patch using the previous snapshot or reverse replacement
 */
export function revertPatchFromFile(
  files: ScannedFile[],
  patch: RemediationPatch
): { updatedFiles: ScannedFile[]; success: boolean; message: string } {
  const fileIndex = files.findIndex(f => f.path === patch.file || f.name === patch.file);
  if (fileIndex === -1) {
    return { updatedFiles: files, success: false, message: `Arquivo ${patch.file} não encontrado.` };
  }

  const targetFile = files[fileIndex];

  // If we have a full snapshot, restore it
  if (patch.previousFileContentSnapshot) {
    const updatedFiles = [...files];
    updatedFiles[fileIndex] = {
      ...targetFile,
      content: patch.previousFileContentSnapshot,
      size: new Blob([patch.previousFileContentSnapshot]).size,
      lastModified: Date.now()
    };
    return {
      updatedFiles,
      success: true,
      message: `Arquivo ${targetFile.name} revertido com sucesso ao estado anterior.`
    };
  }

  // Otherwise reverse replacement
  if (targetFile.content.includes(patch.replacementSnippet.trim())) {
    const revertedContent = targetFile.content.replace(patch.replacementSnippet.trim(), patch.originalSnippet.trim());
    const updatedFiles = [...files];
    updatedFiles[fileIndex] = {
      ...targetFile,
      content: revertedContent,
      size: new Blob([revertedContent]).size,
      lastModified: Date.now()
    };
    return {
      updatedFiles,
      success: true,
      message: `Patch revertido com sucesso em ${targetFile.name}.`
    };
  }

  return {
    updatedFiles: files,
    success: false,
    message: `Não foi possível reverter o patch: o código modificado não foi localizado.`
  };
}

/**
 * Batch applies multiple patches sequentially to files
 */
export function applyBatchPatchesToFiles(
  files: ScannedFile[],
  patches: RemediationPatch[]
): { updatedFiles: ScannedFile[]; appliedCount: number; messages: string[] } {
  let currentFiles = [...files];
  let appliedCount = 0;
  const messages: string[] = [];

  for (const patch of patches) {
    if (patch.status === 'APPLIED') continue;
    const result = applyPatchToFile(currentFiles, patch);
    if (result.success) {
      currentFiles = result.updatedFiles;
      appliedCount++;
      messages.push(`✓ [${patch.file}:${patch.line}] ${patch.title}`);
    } else {
      messages.push(`✗ [${patch.file}:${patch.line}] Falha: ${result.message}`);
    }
  }

  return { updatedFiles: currentFiles, appliedCount, messages };
}

/**
 * Synchronizes environment variables required by patches into the workspace's .env.example
 */
export function syncEnvVariablesToWorkspace(
  files: ScannedFile[],
  patches: RemediationPatch[]
): { updatedFiles: ScannedFile[]; addedVariables: string[] } {
  const envConfigs = patches
    .map(p => p.envConfig)
    .filter((c): c is SuggestedFixEnvConfig => Boolean(c && c.variableName));

  if (envConfigs.length === 0) {
    return { updatedFiles: files, addedVariables: [] };
  }

  let envFile = files.find(f => f.name === '.env.example' || f.name === '.env');
  let content = envFile ? envFile.content : '# Variáveis de Ambiente do SecScan Workspace\n';
  const addedVariables: string[] = [];

  envConfigs.forEach(cfg => {
    if (!content.includes(cfg.variableName)) {
      content += `\n# Injetado pela Auto-Remediação IA para mitigar credencial codificada:\n${cfg.exampleLine || `${cfg.variableName}=sua_chave_ou_token_aqui`}\n`;
      addedVariables.push(cfg.variableName);
    }
  });

  if (addedVariables.length === 0) {
    return { updatedFiles: files, addedVariables: [] };
  }

  const updatedEnvFile: ScannedFile = {
    name: '.env.example',
    path: '.env.example',
    content,
    size: new Blob([content]).size,
    extension: 'env',
    lastModified: Date.now()
  };

  const updatedFiles = envFile
    ? files.map(f => (f.name === envFile!.name ? updatedEnvFile : f))
    : [...files, updatedEnvFile];

  return { updatedFiles, addedVariables };
}
