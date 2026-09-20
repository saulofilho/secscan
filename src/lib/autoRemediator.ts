import { ScannedFile, ScanFinding } from '../types';

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
  category: 'SECRET_EXTRACTION' | 'INJECTION_PREVENTION' | 'DOM_SANITIZATION' | 'INFRA_HARDENING';
  status: 'PENDING' | 'APPLIED' | 'REVERTED';
  cwe: string;
  envSnippetNeeded?: string;
}

export function generateRemediationPatchForFinding(finding: ScanFinding, files: ScannedFile[]): RemediationPatch | null {
  const targetFile = files.find(f => f.path === finding.file);
  if (!targetFile) return null;

  let replacement = '';
  let explanation = '';
  let category: RemediationPatch['category'] = 'SECRET_EXTRACTION';
  let envSnippetNeeded: string | undefined;

  const original = finding.snippet.trim();

  // Pattern 1: Hardcoded Secret / Token in assignment
  if (finding.matchedSecret && (finding.snippet.includes('=') || finding.snippet.includes(':'))) {
    category = 'SECRET_EXTRACTION';
    const envVarName = `SECRET_${finding.ruleId.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`;
    
    if (finding.snippet.includes('const ') || finding.snippet.includes('let ') || finding.snippet.includes('var ')) {
      replacement = finding.snippet.replace(/["'][^"']+["']/, `process.env.${envVarName} || ""`);
    } else if (finding.snippet.includes(':')) {
      replacement = finding.snippet.replace(/:\s*["'][^"']+["']/, `: process.env.${envVarName} || ""`);
    } else {
      replacement = `// REMEDIATED BY SECSCAN: Hardcoded key replaced\nconst secureToken = process.env.${envVarName};`;
    }

    explanation = `Removeu o segredo em texto claro e parametrizou via variável de ambiente 'process.env.${envVarName}'.`;
    envSnippetNeeded = `# .env.example\n${envVarName}=sua_chave_aqui_gerenciada_por_vault`;
  } 
  // Pattern 2: Dangerous eval execution
  else if (finding.snippet.includes('eval(')) {
    category = 'INJECTION_PREVENTION';
    replacement = finding.snippet.replace(/eval\(([^)]+)\)/, 'JSON.parse($1)');
    explanation = 'Substituiu a execução insegura de código arbitrário eval() pelo parser seguro JSON.parse().';
  } 
  // Pattern 3: Unsafe innerHTML
  else if (finding.snippet.includes('.innerHTML')) {
    category = 'DOM_SANITIZATION';
    replacement = finding.snippet.replace(/(\w+)\.innerHTML\s*=\s*(.+);?/, '$1.innerHTML = DOMPurify.sanitize($2);');
    explanation = 'Aplicou a sanitização contextual do DOMPurify para neutralizar payloads de Cross-Site Scripting (XSS).';
  } 
  // Pattern 4: Wildcard postMessage
  else if (finding.snippet.includes('postMessage') && finding.snippet.includes('*')) {
    category = 'INJECTION_PREVENTION';
    replacement = finding.snippet.replace(/postMessage\(([^,]+),\s*["']\*["']\)/, 'postMessage($1, window.location.origin)');
    explanation = 'Restringiu o destino da mensagem da janela para window.location.origin, mitigando vazamento de tokens para iframes maliciosos.';
  } else {
    // Default fallback
    category = 'SECRET_EXTRACTION';
    replacement = `// REMEDIATED: Secure environment retrieval\nprocess.env.APP_SECRET_TOKEN`;
    explanation = 'Isolamento de valor confidencial em cofre de credenciais.';
  }

  const unifiedDiff = `--- a/${finding.file}
+++ b/${finding.file}
@@ -${finding.line},1 +${finding.line},1 @@
-  ${original}
+  ${replacement.trim()}`;

  return {
    id: `patch-${finding.id}`,
    findingId: finding.id,
    title: `Correção Automática: ${finding.ruleName}`,
    file: finding.file,
    line: finding.line,
    originalSnippet: original,
    replacementSnippet: replacement.trim(),
    unifiedDiff,
    explanation,
    category,
    status: 'PENDING',
    cwe: (finding.category as string) === 'DANGEROUS_EVAL' || finding.ruleName.toLowerCase().includes('eval') ? 'CWE-95' : 'CWE-798',
    envSnippetNeeded
  };
}

/**
 * Applies a generated patch directly into the file's content in workspace memory
 */
export function applyPatchToFile(
  files: ScannedFile[],
  patch: RemediationPatch
): { updatedFiles: ScannedFile[]; success: boolean; message: string } {
  const fileIndex = files.findIndex(f => f.path === patch.file);
  if (fileIndex === -1) {
    return { updatedFiles: files, success: false, message: `Arquivo ${patch.file} não encontrado no workspace.` };
  }

  const targetFile = files[fileIndex];
  const lines = targetFile.content.split('\n');

  // Check line matching
  const targetLineIdx = patch.line - 1;
  if (targetLineIdx >= 0 && targetLineIdx < lines.length && lines[targetLineIdx].includes(patch.originalSnippet)) {
    lines[targetLineIdx] = lines[targetLineIdx].replace(patch.originalSnippet, patch.replacementSnippet);
  } else {
    // Fallback search in entire content
    const replacedContent = targetFile.content.replace(patch.originalSnippet, patch.replacementSnippet);
    if (replacedContent === targetFile.content) {
      return { updatedFiles: files, success: false, message: 'Snippet original não coincide mais com o código atual.' };
    }
    const updatedFiles = [...files];
    updatedFiles[fileIndex] = {
      ...targetFile,
      content: replacedContent,
      lastModified: Date.now()
    };
    return { updatedFiles, success: true, message: `Patch aplicado com sucesso em ${patch.file}.` };
  }

  const updatedFiles = [...files];
  updatedFiles[fileIndex] = {
    ...targetFile,
    content: lines.join('\n'),
    lastModified: Date.now()
  };

  return { updatedFiles, success: true, message: `Patch aplicado com sucesso em ${patch.file} (linha ${patch.line}).` };
}
