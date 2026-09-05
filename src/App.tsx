import React, { useState, useEffect, useCallback } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle2, 
  X 
} from 'lucide-react';
import { Header } from './components/Header';
import { DashboardOverview } from './components/DashboardOverview';
import { ScannerView } from './components/ScannerView';
import { ApiPathsView } from './components/ApiPathsView';
import { JsMinerView } from './components/JsMinerView';
import { CustomRulesView } from './components/CustomRulesView';
import { CliTerminalView } from './components/CliTerminalView';
import { CiCdIntegrationView } from './components/CiCdIntegrationView';
import { ExportModal } from './components/ExportModal';
import { QuickTourModal } from './components/QuickTourModal';
import { GlobalIgnoreModal } from './components/GlobalIgnoreModal';
import { SecurityGlossaryModal } from './components/SecurityGlossary';

import { DEFAULT_RULES } from './lib/defaultRules';
import { SAMPLE_FILES } from './lib/sampleFiles';
import { scanSourceFiles, exportToJson, DEFAULT_GLOBAL_IGNORE_PATTERNS } from './lib/scanner';
import { RegexRule, ScannedFile, ScanReport, AuditLogEvent, ScanFinding, IgnorePatternItem } from './types';
import { SecurityGlossaryEntry } from './lib/securityGlossary';
import { safeGetItem, safeSetItem } from './lib/storage';
import { validateFileForSensitivePatterns, isForbiddenWorkspaceFile } from './lib/workspaceValidator';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [files, setFiles] = useState<ScannedFile[]>(SAMPLE_FILES);
  const [rules, setRules] = useState<RegexRule[]>(() => {
    const saved = safeGetItem('secscan_rules');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          // Clean up any stale (?i) from previously saved rules
          return parsed.map((r: RegexRule) => {
            if (r.pattern && r.pattern.startsWith('(?i)')) {
              return {
                ...r,
                pattern: r.pattern.replace(/^\(\?i\)/, ''),
                flags: r.flags && r.flags.includes('i') ? r.flags : (r.flags || '') + 'i'
              };
            }
            return r;
          });
        }
      } catch {
        return DEFAULT_RULES;
      }
    }
    return DEFAULT_RULES;
  });

  // Global Ignore List state (persisted in safe storage)
  const [ignorePatterns, setIgnorePatterns] = useState<IgnorePatternItem[]>(() => {
    const saved = safeGetItem('secscan_ignore_patterns');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      } catch {
        return DEFAULT_GLOBAL_IGNORE_PATTERNS;
      }
    }
    return DEFAULT_GLOBAL_IGNORE_PATTERNS;
  });

  const [selectedFile, setSelectedFile] = useState<ScannedFile | null>(SAMPLE_FILES[0]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEvent[]>([]);
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [showIgnoreModal, setShowIgnoreModal] = useState<boolean>(false);
  const [showGlossaryModal, setShowGlossaryModal] = useState<boolean>(false);
  const [selectedGlossaryId, setSelectedGlossaryId] = useState<string | undefined>(undefined);
  const [validationNotice, setValidationNotice] = useState<{
    type: 'error' | 'warning' | 'success';
    title: string;
    message: string;
  } | null>(null);
  const [showTour, setShowTour] = useState<boolean>(() => {
    return !safeGetItem('secscan_tour_completed');
  });

  const handleCloseTour = () => {
    safeSetItem('secscan_tour_completed', 'true');
    setShowTour(false);
  };

  // Run initial scan
  const [report, setReport] = useState<ScanReport>(() => {
    const safePatterns = Array.isArray(ignorePatterns) ? ignorePatterns : DEFAULT_GLOBAL_IGNORE_PATTERNS;
    const activeIgnoreStrings = safePatterns.filter(p => p && p.enabled).map(p => p.pattern);
    return scanSourceFiles(SAMPLE_FILES, DEFAULT_RULES, activeIgnoreStrings);
  });

  // Execute scan
  const executeScan = useCallback((
    targetFiles: ScannedFile[], 
    targetRules: RegexRule[], 
    targetIgnorePatterns?: IgnorePatternItem[]
  ) => {
    setIsScanning(true);
    const newLogs: AuditLogEvent[] = [];
    const sourcePatterns = Array.isArray(targetIgnorePatterns)
      ? targetIgnorePatterns
      : (Array.isArray(ignorePatterns) ? ignorePatterns : DEFAULT_GLOBAL_IGNORE_PATTERNS);
    const activeIgnoreStrings = sourcePatterns.filter(p => p && p.enabled).map(p => p.pattern);

    const result = scanSourceFiles(targetFiles, targetRules, activeIgnoreStrings, (event) => {
      newLogs.push(event);
    });

    setReport(result);
    setAuditLogs(prev => [...newLogs.reverse(), ...prev].slice(0, 80));
    setIsScanning(false);
  }, [ignorePatterns]);

  // Run on first load
  useEffect(() => {
    executeScan(files, rules, ignorePatterns);
  }, []);

  // Persist rules in safe storage
  useEffect(() => {
    safeSetItem('secscan_rules', JSON.stringify(rules));
  }, [rules]);

  // Persist ignore patterns in safe storage
  useEffect(() => {
    safeSetItem('secscan_ignore_patterns', JSON.stringify(ignorePatterns));
  }, [ignorePatterns]);

  // Global ignore list handlers
  const handleSaveIgnorePatterns = (newPatterns: IgnorePatternItem[]) => {
    setIgnorePatterns(newPatterns);
    executeScan(files, rules, newPatterns);
  };

  const handleToggleIgnorePattern = (id: string) => {
    const updated = ignorePatterns.map(p => p.id === id ? { ...p, enabled: !p.enabled } : p);
    setIgnorePatterns(updated);
    executeScan(files, rules, updated);
  };

  const handleQuickIgnore = (pattern: string, description?: string) => {
    const existingIndex = ignorePatterns.findIndex(p => p.pattern.toLowerCase() === pattern.toLowerCase());
    let updated: IgnorePatternItem[];
    if (existingIndex >= 0) {
      updated = ignorePatterns.map((p, idx) => idx === existingIndex ? { ...p, enabled: true } : p);
    } else {
      const newItem: IgnorePatternItem = {
        id: `custom-ignore-${Date.now()}`,
        pattern,
        enabled: true,
        description: description || `Exclusão rápida (${pattern})`,
        isBuiltIn: false,
        createdAt: new Date().toISOString().split('T')[0]
      };
      updated = [newItem, ...ignorePatterns];
    }
    setIgnorePatterns(updated);
    executeScan(files, rules, updated);
  };

  // Security Glossary handlers
  const handleOpenGlossary = (entry?: SecurityGlossaryEntry) => {
    if (entry) {
      setSelectedGlossaryId(entry.id);
    }
    setShowGlossaryModal(true);
  };

  // Handle file uploads with pre-flight security validation
  const handleFileUpload = (uploadedFiles: FileList) => {
    const newScannedFiles: ScannedFile[] = [];
    const blockedFiles: string[] = [];
    const warningFiles: string[] = [];
    const readers: Promise<void>[] = [];

    Array.from(uploadedFiles).forEach((file) => {
      // 1. Immediately check for forbidden file names (.env, .pem, id_rsa, etc.)
      const nameCheck = isForbiddenWorkspaceFile(file.name);
      if (nameCheck.isForbidden) {
        blockedFiles.push(`${file.name} (${nameCheck.reason})`);
        return;
      }

      const promise = new Promise<void>((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          const content = (e.target?.result as string) || '';
          
          // 2. Validate file content for real non-placeholder secrets
          const validation = validateFileForSensitivePatterns(file.name, content);

          if (validation.isForbiddenFile || validation.hasBlockers) {
            blockedFiles.push(`${file.name} [${validation.findings.map(f => f.name).join(', ')}]`);
          } else {
            if (validation.hasWarnings) {
              warningFiles.push(`${file.name} (${validation.findings.length} aviso(s))`);
            }
            const path = (file as any).webkitRelativePath || file.name;
            const ext = file.name.split('.').pop() || '';
            newScannedFiles.push({
              name: file.name,
              path,
              content,
              size: file.size,
              extension: ext
            });
          }
          resolve();
        };
        reader.readAsText(file);
      });
      readers.push(promise);
    });

    Promise.all(readers).then(() => {
      if (blockedFiles.length > 0) {
        setValidationNotice({
          type: 'error',
          title: 'Arquivos Sensíveis Bloqueados',
          message: `Os seguintes arquivos não puderam ser adicionados por conterem variáveis de ambiente (.env) ou chaves privadas críticas: ${blockedFiles.join('; ')}`
        });
      } else if (warningFiles.length > 0) {
        setValidationNotice({
          type: 'warning',
          title: 'Importação com Alertas de Padrões',
          message: `Arquivos importados com potenciais tokens detectados: ${warningFiles.join('; ')}`
        });
      } else if (newScannedFiles.length > 0) {
        setValidationNotice({
          type: 'success',
          title: 'Importação Segura Concluída',
          message: `${newScannedFiles.length} arquivo(s) validado(s) com sucesso e adicionado(s) ao workspace.`
        });
      }

      if (newScannedFiles.length > 0) {
        const merged = [...files, ...newScannedFiles];
        setFiles(merged);
        setSelectedFile(newScannedFiles[0] || files[0]);
        executeScan(merged, rules);
        setActiveTab('scanner');
      }
    });
  };

  // Add custom file via paste with pre-flight security validation
  const handleAddCustomFile = (name: string, content: string) => {
    const validation = validateFileForSensitivePatterns(name, content);
    if (validation.isForbiddenFile || validation.hasBlockers) {
      setValidationNotice({
        type: 'error',
        title: 'Arquivo Bloqueado',
        message: validation.blockedReason || `Não é permitido adicionar arquivos de ambiente (.env) ou segredos críticos não mascarados (${validation.findings.map(f => f.name).join(', ')}).`
      });
      return;
    }

    const newFile: ScannedFile = {
      name,
      path: `src/pasted/${name}`,
      content,
      size: content.length,
      extension: name.split('.').pop() || 'js'
    };

    const updated = [newFile, ...files];
    setFiles(updated);
    setSelectedFile(newFile);
    executeScan(updated, rules);
    setValidationNotice({
      type: 'success',
      title: 'Arquivo Adicionado',
      message: `O arquivo ${name} foi validado e inserido no workspace com sucesso.`
    });
  };

  // Reset to initial sample repository
  const handleResetWorkspace = () => {
    setFiles(SAMPLE_FILES);
    setSelectedFile(SAMPLE_FILES[0]);
    executeScan(SAMPLE_FILES, rules);
  };

  // Toggle rule
  const handleToggleRule = (ruleId: string) => {
    const updated = rules.map(r => r.id === ruleId ? { ...r, enabled: !r.enabled } : r);
    setRules(updated);
    executeScan(files, updated);
  };

  // Add rule
  const handleAddRule = (newRule: RegexRule) => {
    const updated = [newRule, ...rules];
    setRules(updated);
    executeScan(files, updated);
  };

  // Delete rule
  const handleDeleteRule = (ruleId: string) => {
    const updated = rules.filter(r => r.id !== ruleId);
    setRules(updated);
    executeScan(files, updated);
  };

  // Export rules
  const handleExportRules = () => {
    const json = JSON.stringify(rules, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'secscan-regex-rules.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Import rules
  const handleImportRules = (imported: RegexRule[]) => {
    setRules(imported);
    executeScan(files, imported);
  };

  // Select finding from overview card to inspect in code viewer
  const handleSelectFinding = (finding: ScanFinding) => {
    const targetFile = files.find(f => f.path === finding.file);
    if (targetFile) {
      setSelectedFile(targetFile);
      setActiveTab('scanner');
    }
  };

  // Select file directly from path
  const handleSelectFileByPath = (filePath: string) => {
    const targetFile = files.find(f => f.path === filePath);
    if (targetFile) {
      setSelectedFile(targetFile);
      setActiveTab('scanner');
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-[#E0E0E0] flex flex-col font-sans selection:bg-[#FF3E00] selection:text-white">
      {/* Top Navigation & App Bar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        report={report}
        isScanning={isScanning}
        onRunScan={() => executeScan(files, rules, ignorePatterns)}
        onOpenExport={() => setShowExportModal(true)}
        onResetWorkspace={handleResetWorkspace}
        onOpenTour={() => setShowTour(true)}
        onOpenIgnoreModal={() => setShowIgnoreModal(true)}
        activeIgnoreCount={ignorePatterns.filter(p => p.enabled).length}
        onOpenGlossary={() => handleOpenGlossary()}
      />

      {/* Main Container Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6 pb-12">
        {/* Workspace Ingestion & Security Validation Banner */}
        {validationNotice && (
          <div 
            id="workspace-validation-notice"
            className={`mb-6 p-4 rounded-xl border flex items-start justify-between gap-4 transition-all duration-200 ${
              validationNotice.type === 'error'
                ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
                : validationNotice.type === 'warning'
                ? 'bg-amber-950/40 border-amber-800/60 text-amber-200'
                : 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
            }`}
          >
            <div className="flex items-start gap-3">
              {validationNotice.type === 'error' ? (
                <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              ) : validationNotice.type === 'warning' ? (
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              )}
              <div>
                <h4 className="text-sm font-semibold tracking-wide">
                  {validationNotice.title}
                </h4>
                <p className="text-xs mt-1 leading-relaxed opacity-90">
                  {validationNotice.message}
                </p>
              </div>
            </div>
            <button
              id="btn-dismiss-validation-notice"
              onClick={() => setValidationNotice(null)}
              className="p-1.5 rounded-lg hover:bg-white/10 text-white/70 hover:text-white transition-colors"
              title="Fechar aviso"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {activeTab === 'dashboard' && (
          <DashboardOverview
            report={report}
            auditLogs={auditLogs}
            onSelectFinding={handleSelectFinding}
            onNavigateToTab={setActiveTab}
            onNavigateToFile={handleSelectFileByPath}
            onOpenTour={() => setShowTour(true)}
            onOpenExport={() => setShowExportModal(true)}
            ignorePatterns={ignorePatterns}
            onOpenIgnoreModal={() => setShowIgnoreModal(true)}
            onToggleIgnorePattern={handleToggleIgnorePattern}
            onOpenGlossary={handleOpenGlossary}
          />
        )}

        {activeTab === 'scanner' && (
          <ScannerView
            files={files}
            findings={report.findings}
            selectedFile={selectedFile}
            onSelectFile={setSelectedFile}
            onFileUpload={handleFileUpload}
            onAddCustomFile={handleAddCustomFile}
            ignorePatterns={ignorePatterns}
            onOpenIgnoreModal={() => setShowIgnoreModal(true)}
            onQuickIgnore={handleQuickIgnore}
            onOpenGlossary={handleOpenGlossary}
          />
        )}

        {activeTab === 'endpoints' && (
          <ApiPathsView
            endpoints={report.apiEndpoints}
          />
        )}

        {activeTab === 'jsminer' && (
          <JsMinerView
            jsMiner={report.jsMiner}
          />
        )}

        {activeTab === 'rules' && (
          <CustomRulesView
            rules={rules}
            onToggleRule={handleToggleRule}
            onAddRule={handleAddRule}
            onDeleteRule={handleDeleteRule}
            onExportRules={handleExportRules}
            onImportRules={handleImportRules}
          />
        )}

        {activeTab === 'cli' && (
          <CliTerminalView
            report={report}
            onTriggerScan={() => executeScan(files, rules, ignorePatterns)}
          />
        )}

        {activeTab === 'cicd' && (
          <CiCdIntegrationView
            report={report}
          />
        )}
      </main>

      {/* Footer Status Bar */}
      <footer className="border-t border-[#1F1F1F] bg-[#0A0A0A] py-3 px-4 sm:px-8 text-[11px] font-mono text-[#666] flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 text-white font-bold">
            <span className="w-2 h-2 rounded-none bg-[#00FF41] inline-block animate-pulse"></span>
            SECSCAN_ENGINE // OPERATIONAL
          </span>
          <span className="text-[#444]">|</span>
          <span>RULES_V4_LOADED: {rules.length}</span>
          <span className="text-[#444] hidden sm:inline">|</span>
          <span className="hidden sm:inline">IGNORE_PATTERNS: {ignorePatterns.filter(p => p.enabled).length} ATIVOS</span>
          <span className="text-[#444] hidden sm:inline">|</span>
          <span className="hidden sm:inline">MEMORY: LOCAL_CONTAINER</span>
        </div>

        <div className="flex items-center gap-4 text-[#888]">
          <span>NODE 22 LTS SAST SPECIFICATION</span>
          <span className="text-[#444]">|</span>
          <span className="text-[#FF3E00] font-bold">ZERO_DEPENDENCY_LEAK</span>
        </div>
      </footer>

      {/* Export Modal */}
      {showExportModal && (
        <ExportModal
          report={report}
          onClose={() => setShowExportModal(false)}
        />
      )}

      {/* Quick Tour Modal */}
      <QuickTourModal
        isOpen={showTour}
        onClose={handleCloseTour}
        onNavigateToTab={setActiveTab}
      />

      {/* Global Ignore List Modal */}
      <GlobalIgnoreModal
        isOpen={showIgnoreModal}
        onClose={() => setShowIgnoreModal(false)}
        patterns={ignorePatterns}
        onUpdatePatterns={handleSaveIgnorePatterns}
        onSavePatterns={handleSaveIgnorePatterns}
        onTogglePattern={handleToggleIgnorePattern}
        workspaceFiles={files}
        onTriggerRescan={() => executeScan(files, rules, ignorePatterns)}
      />

      {/* Security Glossary Modal */}
      <SecurityGlossaryModal
        isOpen={showGlossaryModal}
        onClose={() => setShowGlossaryModal(false)}
        selectedEntryId={selectedGlossaryId}
      />
    </div>
  );
}
