import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle2, 
  X,
  Loader2,
  ChevronDown,
  ChevronUp,
  FileCode,
  Terminal,
  Filter,
  Copy,
  Check,
  Trash2,
  RefreshCw,
  FileText,
  Clock
} from 'lucide-react';
import { Header } from './components/Header';
import { DashboardOverview } from './components/DashboardOverview';
import { ScannerView } from './components/ScannerView';
import { ApiPathsView } from './components/ApiPathsView';
import { JsMinerView } from './components/JsMinerView';
import { DataFlowGraphView } from './components/DataFlowGraphView';
import { CustomRulesView } from './components/CustomRulesView';
import { CliTerminalView } from './components/CliTerminalView';
import { CiCdIntegrationView } from './components/CiCdIntegrationView';
import { ExportModal } from './components/ExportModal';
import { QuickTourModal } from './components/QuickTourModal';
import { WelcomeWorkspaceModal } from './components/WelcomeWorkspaceModal';
import { GlobalIgnoreModal } from './components/GlobalIgnoreModal';
import { SecurityGlossaryModal } from './components/SecurityGlossary';
import { SnippetHighlighter } from './components/SnippetHighlighter';
import { WorkspaceFilesMetaPopover } from './components/WorkspaceFilesMetaPopover';
import { ValidationSeverityDonutChart } from './components/ValidationSeverityDonutChart';
import { GlobalScanProgressBar } from './components/GlobalScanProgressBar';
import { CommandPaletteModal } from './components/CommandPaletteModal';
import { KeyboardShortcutsModal } from './components/KeyboardShortcutsModal';
import { SeverityTooltip } from './components/Tooltip';
import { SecScanMttrConfigModal } from './components/SecScanMttrConfigModal';
import { MttrMiniTrendlineChart, parseRemediationHours } from './components/MttrMiniTrendlineChart';
import { SecurityFrameworksHub } from './components/SecurityFrameworksHub';
import { SecurityOnionSocView } from './components/SecurityOnionSocView';
import { CrowdStrikeSuiteView } from './components/CrowdStrikeSuiteView';
import { NmapNetworkSuiteView } from './components/NmapNetworkSuiteView';
import { NiktoWebScannerView } from './components/NiktoWebScannerView';
import { NgfwSuiteView } from './components/NgfwSuiteView';
import { EdrSuiteView } from './components/EdrSuiteView';
import { IdsIpsSuiteView } from './components/IdsIpsSuiteView';
import { DnsSecuritySuiteView } from './components/DnsSecuritySuiteView';
import { WafSuiteView } from './components/WafSuiteView';
import { SdwanSuiteView } from './components/SdwanSuiteView';

import { DEFAULT_RULES } from './lib/defaultRules';
import { SAMPLE_FILES } from './lib/sampleFiles';
import { scanSourceFiles, scanSourceFilesAsync, exportToJson, DEFAULT_GLOBAL_IGNORE_PATTERNS } from './lib/scanner';
import { RegexRule, ScannedFile, ScanReport, AuditLogEvent, ScanFinding, IgnorePatternItem, ScanProgress, SecScanGlobalConfig } from './types';
import { SecurityGlossaryEntry } from './lib/securityGlossary';
import { safeGetItem, safeSetItem } from './lib/storage';
import { getSecScanConfig, calculateDynamicRemediationTime } from './lib/secscanConfig';
import { 
  validateFileForSensitivePatterns, 
  isForbiddenWorkspaceFile,
  SensitivePatternFinding,
  resolveSecurityImpact
} from './lib/workspaceValidator';

export interface NoticeDetailItem {
  fileName: string;
  blockedReason?: string;
  status: 'BLOCKED' | 'WARNING' | 'VALIDATED';
  findings: SensitivePatternFinding[];
}

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [files, setFiles] = useState<ScannedFile[]>([]);
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

  const [selectedFile, setSelectedFile] = useState<ScannedFile | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEvent[]>([]);
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [showIgnoreModal, setShowIgnoreModal] = useState<boolean>(false);
  const [showGlossaryModal, setShowGlossaryModal] = useState<boolean>(false);
  const [selectedGlossaryId, setSelectedGlossaryId] = useState<string | undefined>(undefined);
  const [showCommandPalette, setShowCommandPalette] = useState<boolean>(false);
  const [showShortcutsModal, setShowShortcutsModal] = useState<boolean>(false);
  const [showMttrConfigModal, setShowMttrConfigModal] = useState<boolean>(false);
  const [shortcutToast, setShortcutToast] = useState<{ message: string; key?: string } | null>(null);

  // Global SecScan configuration for dynamic remediationTime (MTTR) parameters
  const [secScanConfig, setSecScanConfig] = useState<SecScanGlobalConfig>(() => getSecScanConfig());

  useEffect(() => {
    const handleConfigChange = (e: Event) => {
      const customEvent = e as CustomEvent<SecScanGlobalConfig>;
      if (customEvent.detail) {
        setSecScanConfig(customEvent.detail);
      }
    };
    window.addEventListener('secscan-config-changed', handleConfigChange);
    return () => window.removeEventListener('secscan-config-changed', handleConfigChange);
  }, []);

  const isMac = useMemo(() => {
    return typeof window !== 'undefined' && /Mac|iPod|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  }, []);
  const [validationNotice, setValidationNotice] = useState<{
    type: 'error' | 'warning' | 'success';
    title: string;
    message: string;
    phase?: string;
    details?: NoticeDetailItem[];
  } | null>(null);
  const [isNoticeDetailsOpen, setIsNoticeDetailsOpen] = useState<boolean>(false);

  const noticeSeverityDistribution = useMemo(() => {
    if (!validationNotice?.details || validationNotice.details.length === 0) {
      return { critical: 0, high: 0, warning: 0, total: 0 };
    }
    let critical = 0;
    let high = 0;
    let warning = 0;

    validationNotice.details.forEach(detail => {
      if (detail.blockedReason && (!detail.findings || detail.findings.length === 0)) {
        critical += 1;
      }
      detail.findings?.forEach(f => {
        if (f.severity === 'CRITICAL') {
          critical += 1;
        } else if (f.severity === 'HIGH') {
          high += 1;
        } else {
          warning += 1;
        }
      });
    });

    const total = critical + high + warning;
    return { critical, high, warning, total };
  }, [validationNotice]);

  const workspaceCurrentMttrHours = useMemo(() => {
    if (noticeSeverityDistribution.total === 0) return 0;
    const critHours = parseRemediationHours(
      secScanConfig.severityConfig?.CRITICAL?.remediationTime || secScanConfig.remediationTime?.CRITICAL,
      1.75
    );
    const highHours = parseRemediationHours(
      secScanConfig.severityConfig?.HIGH?.remediationTime || secScanConfig.remediationTime?.HIGH,
      5.0
    );
    const warnHours = parseRemediationHours(
      secScanConfig.severityConfig?.WARNING?.remediationTime || secScanConfig.remediationTime?.WARNING,
      18.0
    );
    const totalHours =
      noticeSeverityDistribution.critical * critHours +
      noticeSeverityDistribution.high * highHours +
      noticeSeverityDistribution.warning * warnHours;
    return Number((totalHours / noticeSeverityDistribution.total).toFixed(1));
  }, [noticeSeverityDistribution, secScanConfig]);

  const maxAllowedMttrLimit =
    typeof secScanConfig.maxAllowedMttrHours === 'number' && !isNaN(secScanConfig.maxAllowedMttrHours) && secScanConfig.maxAllowedMttrHours > 0
      ? secScanConfig.maxAllowedMttrHours
      : 4.0;

  const isWorkspaceMttrExceeded =
    noticeSeverityDistribution.total > 0 && workspaceCurrentMttrHours > maxAllowedMttrLimit;

  const [noticeSeverityFilters, setNoticeSeverityFilters] = useState<{
    CRITICAL: boolean;
    HIGH: boolean;
    WARNING: boolean;
  }>({
    CRITICAL: true,
    HIGH: true,
    WARNING: true,
  });

  const toggleNoticeSeverityFilter = (level: 'CRITICAL' | 'HIGH' | 'WARNING') => {
    setNoticeSeverityFilters(prev => ({
      ...prev,
      [level]: !prev[level]
    }));
  };

  const resetNoticeSeverityFilters = () => {
    setNoticeSeverityFilters({
      CRITICAL: true,
      HIGH: true,
      WARNING: true
    });
  };

  const filteredNoticeDetails = useMemo(() => {
    if (!validationNotice?.details) return [];
    return validationNotice.details.map(detail => {
      const showBlockedPolicy = detail.blockedReason ? noticeSeverityFilters.CRITICAL : false;
      const visibleFindings = (detail.findings || []).filter(f => noticeSeverityFilters[f.severity as 'CRITICAL' | 'HIGH' | 'WARNING']);
      const isCleanFile = !detail.blockedReason && (!detail.findings || detail.findings.length === 0);
      const hiddenByFilterCount = ((detail.blockedReason && !noticeSeverityFilters.CRITICAL) ? 1 : 0) + 
        (detail.findings || []).filter(f => !noticeSeverityFilters[f.severity as 'CRITICAL' | 'HIGH' | 'WARNING']).length;

      return {
        ...detail,
        showBlockedPolicy,
        visibleFindings,
        isCleanFile,
        hiddenByFilterCount,
        hasVisibleContent: showBlockedPolicy || visibleFindings.length > 0 || (isCleanFile && (noticeSeverityFilters.CRITICAL || noticeSeverityFilters.HIGH || noticeSeverityFilters.WARNING))
      };
    });
  }, [validationNotice?.details, noticeSeverityFilters]);
  const [showWelcomeModal, setShowWelcomeModal] = useState<boolean>(() => {
    return !safeGetItem('secscan_welcome_completed');
  });

  const handleExploreWithMock = () => {
    safeSetItem('secscan_welcome_completed', 'true');
    setShowWelcomeModal(false);
    setFiles(SAMPLE_FILES);
    setSelectedFile(SAMPLE_FILES[0]);

    // Compute validation notice for sample files
    const noticeDetails: NoticeDetailItem[] = [];
    const blockedFiles: string[] = [];
    const warningFiles: string[] = [];

    SAMPLE_FILES.forEach((file) => {
      const nameCheck = isForbiddenWorkspaceFile(file.name);
      if (nameCheck.isForbidden) {
        blockedFiles.push(`${file.name} (${nameCheck.reason})`);
        noticeDetails.push({
          fileName: file.name,
          blockedReason: nameCheck.reason,
          status: 'BLOCKED',
          findings: [
            {
              patternId: 'forbidden-filename',
              name: 'Arquivo Bloqueado',
              severity: 'CRITICAL',
              description: nameCheck.reason || 'Tipo de arquivo restrito.',
              matchedPreview: file.name,
              line: 1,
              remediation: 'Não envie arquivos de configuração de ambiente (.env) ou chaves privadas.',
              securityImpact: 'Credentials exposure risk (Master environment keys & private certificates)'
            }
          ]
        });
        return;
      }

      const validation = validateFileForSensitivePatterns(file.name, file.content);
      if (validation.isForbiddenFile || validation.hasBlockers) {
        blockedFiles.push(`${file.name} [${validation.findings.map(f => f.name).join(', ')}]`);
        noticeDetails.push({
          fileName: file.name,
          blockedReason: validation.blockedReason,
          status: 'BLOCKED',
          findings: validation.findings
        });
      } else if (validation.hasWarnings) {
        warningFiles.push(`${file.name} (${validation.findings.length} aviso(s))`);
        noticeDetails.push({
          fileName: file.name,
          status: 'WARNING',
          findings: validation.findings
        });
      } else {
        noticeDetails.push({
          fileName: file.name,
          status: 'VALIDATED',
          findings: []
        });
      }
    });

    if (blockedFiles.length > 0) {
      setValidationNotice({
        type: 'error',
        title: 'Arquivos Sensíveis Bloqueados',
        phase: 'Blocked',
        message: `Violações detectadas durante a verificação de integridade: ${blockedFiles.join('; ')}`,
        details: noticeDetails.filter(d => d.status === 'BLOCKED')
      });
      setIsNoticeDetailsOpen(true);
    } else if (warningFiles.length > 0) {
      setValidationNotice({
        type: 'warning',
        title: 'Varredura com Alertas de Padrões',
        phase: 'Filtered',
        message: `Análise concluída com potenciais tokens detectados: ${warningFiles.join('; ')}`,
        details: noticeDetails.filter(d => d.status === 'WARNING')
      });
      setIsNoticeDetailsOpen(true);
    } else {
      setValidationNotice(null);
      setIsNoticeDetailsOpen(false);
    }

    executeScan(SAMPLE_FILES, rules, ignorePatterns);

    const mockEvent: AuditLogEvent = {
      id: `audit-mock-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'SCAN_COMPLETE',
      message: `${SAMPLE_FILES.length} arquivos demonstrativos carregados no workspace.`,
      severity: 'LOW',
      details: { action: 'EXPLORE_WITH_MOCK', filesCount: SAMPLE_FILES.length }
    };
    setAuditLogs(prev => [mockEvent, ...prev].slice(0, 80));
  };

  const handleStartCleanWorkspace = () => {
    safeSetItem('secscan_welcome_completed', 'true');
    setShowWelcomeModal(false);
    handleClearAllFilesAndValidation();
  };

  const [showTour, setShowTour] = useState<boolean>(() => {
    return !safeGetItem('secscan_tour_completed');
  });

  const handleCloseTour = () => {
    safeSetItem('secscan_tour_completed', 'true');
    setShowTour(false);
  };

  // Run initial scan (starts clean with 0 files by default)
  const [report, setReport] = useState<ScanReport>(() => {
    const safePatterns = Array.isArray(ignorePatterns) ? ignorePatterns : DEFAULT_GLOBAL_IGNORE_PATTERNS;
    const activeIgnoreStrings = safePatterns.filter(p => p && p.enabled).map(p => p.pattern);
    return scanSourceFiles([], DEFAULT_RULES, activeIgnoreStrings);
  });

  const [previousWorkspaceSize, setPreviousWorkspaceSize] = useState<number | undefined>(undefined);
  const lastScanWorkspaceBytesRef = useRef<number | null>(null);

  // Global scan progress tracking
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const activeScanSequenceRef = useRef<number>(0);

  // Execute scan
  const executeScan = useCallback(async (
    targetFiles: ScannedFile[], 
    targetRules: RegexRule[], 
    targetIgnorePatterns?: IgnorePatternItem[]
  ) => {
    const currentSeq = ++activeScanSequenceRef.current;
    setIsScanning(true);
    setScanProgress({
      percentage: 0,
      currentFileIndex: 0,
      totalFiles: targetFiles.length,
      currentFileName: targetFiles[0]?.name || '',
      currentFilePath: targetFiles[0]?.path || '',
      phase: 'INITIALIZING',
      phaseLabel: 'Inicializando motor SAST...',
      findingsFoundCount: 0,
      scannedCount: 0,
      ignoredCount: 0,
      elapsedMs: 0
    });

    const newLogs: AuditLogEvent[] = [];
    const sourcePatterns = Array.isArray(targetIgnorePatterns)
      ? targetIgnorePatterns
      : (Array.isArray(ignorePatterns) ? ignorePatterns : DEFAULT_GLOBAL_IGNORE_PATTERNS);
    const activeIgnoreStrings = sourcePatterns.filter(p => p && p.enabled).map(p => p.pattern);

    const currentWorkspaceBytes = targetFiles.reduce((acc, f) => {
      return acc + (f.size ?? (f.content ? new Blob([f.content]).size : 0));
    }, 0);

    if (lastScanWorkspaceBytesRef.current !== null && lastScanWorkspaceBytesRef.current !== currentWorkspaceBytes) {
      setPreviousWorkspaceSize(lastScanWorkspaceBytesRef.current);
    }
    lastScanWorkspaceBytesRef.current = currentWorkspaceBytes;

    try {
      const result = await scanSourceFilesAsync(
        targetFiles, 
        targetRules, 
        activeIgnoreStrings, 
        (event) => {
          newLogs.push(event);
        },
        (prog) => {
          if (activeScanSequenceRef.current === currentSeq) {
            setScanProgress(prog);
          }
        }
      );

      if (activeScanSequenceRef.current === currentSeq) {
        setReport(result);
        setAuditLogs(prev => [...newLogs.reverse(), ...prev].slice(0, 80));
      }
    } catch (err) {
      console.error('Error in executeScan:', err);
    } finally {
      if (activeScanSequenceRef.current === currentSeq) {
        setIsScanning(false);
      }
    }
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

  const handleApplyFix = (finding: ScanFinding, newSnippet: string) => {
    const targetFilePath = finding.file;
    const targetFile = files.find(f => f.path === targetFilePath || f.name === targetFilePath);

    if (!targetFile) {
      console.warn('Arquivo não encontrado para aplicação de correção:', targetFilePath);
      return;
    }

    let updatedContent = targetFile.content;
    const originalSnippet = finding.snippet || finding.matchedSecret || '';

    if (originalSnippet && updatedContent.includes(originalSnippet)) {
      updatedContent = updatedContent.replace(originalSnippet, newSnippet);
    } else {
      const lines = updatedContent.split('\n');
      const lineIdx = Math.max(0, finding.line - 1);
      if (lineIdx < lines.length) {
        lines[lineIdx] = newSnippet;
        updatedContent = lines.join('\n');
      }
    }

    const updatedFiles = files.map(f => {
      if (f.path === targetFile.path) {
        return {
          ...f,
          content: updatedContent,
          size: new Blob([updatedContent]).size,
          lastModified: Date.now()
        };
      }
      return f;
    });

    setFiles(updatedFiles);
    if (selectedFile?.path === targetFile.path) {
      setSelectedFile({
        ...selectedFile,
        content: updatedContent,
        size: new Blob([updatedContent]).size,
        lastModified: Date.now()
      });
    }

    const newLog: AuditLogEvent = {
      id: `audit-fix-${Date.now()}`,
      timestamp: new Date().toISOString(),
      type: 'FIX_APPLIED',
      message: `Patch seguro aplicado com sucesso ao arquivo ${targetFile.name} (linha ${finding.line}) para ${finding.ruleName}.`,
      severity: finding.severity,
      details: {
        file: targetFile.path,
        line: finding.line,
        ruleName: finding.ruleName
      }
    };
    setAuditLogs(prev => [newLog, ...prev]);

    // Re-run scan with updated code to evaluate risk reduction
    executeScan(updatedFiles, rules, ignorePatterns);
  };

  const handleBatchQuickIgnore = (filePaths: string[]) => {
    if (filePaths.length === 0) return;
    const newPatterns: IgnorePatternItem[] = [];
    let updated = [...ignorePatterns];

    filePaths.forEach((path) => {
      const existingIndex = updated.findIndex(p => p.pattern.toLowerCase() === path.toLowerCase());
      if (existingIndex >= 0) {
        updated = updated.map((p, idx) => idx === existingIndex ? { ...p, enabled: true } : p);
      } else {
        const fileName = path.split('/').pop() || path;
        newPatterns.push({
          id: `custom-ignore-batch-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          pattern: path,
          enabled: true,
          description: `Exclusão rápida em lote (${fileName})`,
          isBuiltIn: false,
          createdAt: new Date().toISOString().split('T')[0]
        });
      }
    });

    const finalPatterns = [...newPatterns, ...updated];
    setIgnorePatterns(finalPatterns);
    executeScan(files, rules, finalPatterns);

    const auditEvent: AuditLogEvent = {
      id: `audit-ignore-batch-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'SCAN_COMPLETE',
      message: `${filePaths.length} arquivo(s) adicionado(s) à lista de ignorados em lote.`,
      severity: 'LOW',
      details: { ignoredPaths: filePaths }
    };
    setAuditLogs(prev => [auditEvent, ...prev].slice(0, 80));
  };

  const handleBatchDeleteFiles = (filePaths: string[]) => {
    if (filePaths.length === 0) return;
    const pathSet = new Set(filePaths);
    const updatedFiles = files.filter(f => !pathSet.has(f.path) && !pathSet.has(f.name));
    setFiles(updatedFiles);
    if (selectedFile && (pathSet.has(selectedFile.path) || pathSet.has(selectedFile.name))) {
      setSelectedFile(updatedFiles[0] || null);
    }
    executeScan(updatedFiles, rules, ignorePatterns);

    const deleteEvent: AuditLogEvent = {
      id: `audit-batch-del-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'SCAN_COMPLETE',
      message: `${filePaths.length} arquivo(s) removido(s) do workspace em lote.`,
      severity: 'LOW',
      details: { deletedPaths: filePaths }
    };
    setAuditLogs(prev => [deleteEvent, ...prev].slice(0, 80));
  };

  // Security Glossary handlers
  const handleOpenGlossary = (entry?: SecurityGlossaryEntry) => {
    if (entry) {
      setSelectedGlossaryId(entry.id);
    }
    setShowGlossaryModal(true);
  };

  // State and handlers for Validation Notice Copy Log, Clear All, and Files Metadata Popover
  const [isLogCopied, setIsLogCopied] = useState<boolean>(false);
  const [showFilesMetaPopover, setShowFilesMetaPopover] = useState<boolean>(false);

  const handleCopyFindingsLog = useCallback(() => {
    if (!validationNotice) return;

    const lines: string[] = [];
    lines.push(`=======================================================`);
    lines.push(`WORKSPACE INGESTION VALIDATION AUDIT REPORT`);
    lines.push(`Generated: ${new Date().toLocaleString()}`);
    lines.push(`Status: ${validationNotice.phase || validationNotice.type.toUpperCase()}`);
    lines.push(`Title: ${validationNotice.title}`);
    lines.push(`Message: ${validationNotice.message}`);
    lines.push(`=======================================================\n`);

    if (!validationNotice.details || validationNotice.details.length === 0) {
      lines.push(`Pre-Flight Ingestion: No violations detected.`);
    } else {
      validationNotice.details.forEach((detail, idx) => {
        lines.push(`[${idx + 1}] File: ${detail.fileName} (Status: ${detail.status})`);
        if (detail.blockedReason) {
          lines.push(`    POLICY VIOLATION: ${detail.blockedReason}`);
        }
        if (detail.findings && detail.findings.length > 0) {
          detail.findings.forEach((f, fIdx) => {
            lines.push(`    - Finding #${fIdx + 1}: [${f.severity}] ${f.name} (Pattern: ${f.patternId}, Line: ${f.line})`);
            lines.push(`      Security Impact: ${f.securityImpact || resolveSecurityImpact(f)}`);
            lines.push(`      Description: ${f.description}`);
            if (f.matchedPreview) {
              lines.push(`      Preview: ${f.matchedPreview}`);
            }
            if (f.remediation) {
              lines.push(`      Remediation: ${f.remediation}`);
            }
          });
        } else if (!detail.blockedReason) {
          lines.push(`    Clean: No sensitive secrets or tokens detected.`);
        }
        lines.push(``);
      });
    }

    const logContent = lines.join('\n');
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(logContent).then(() => {
        setIsLogCopied(true);
        setTimeout(() => setIsLogCopied(false), 2000);
      }).catch(() => {
        const textarea = document.createElement('textarea');
        textarea.value = logContent;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        setIsLogCopied(true);
        setTimeout(() => setIsLogCopied(false), 2000);
      });
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = logContent;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setIsLogCopied(true);
      setTimeout(() => setIsLogCopied(false), 2000);
    }
  }, [validationNotice]);

  const handleClearAllFilesAndValidation = useCallback(() => {
    setFiles([]);
    setSelectedFile(null);
    setValidationNotice(null);
    setIsNoticeDetailsOpen(false);
    executeScan([], rules, ignorePatterns);
    const clearEvent: AuditLogEvent = {
      id: `audit-clear-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'SCAN_COMPLETE',
      message: 'All current files were removed and validation state was reset to empty.',
      severity: 'LOW',
      details: { action: 'CLEAR_ALL' }
    };
    setAuditLogs(prev => [clearEvent, ...prev].slice(0, 80));
  }, [executeScan, rules, ignorePatterns]);

  // Quick Rescan handler to re-run scanning engine and refresh validation without full reload
  const handleQuickRescan = useCallback(() => {
    if (files.length > 0) {
      const noticeDetails: NoticeDetailItem[] = [];
      const blockedFiles: string[] = [];
      const warningFiles: string[] = [];

      files.forEach((file) => {
        const nameCheck = isForbiddenWorkspaceFile(file.name);
        if (nameCheck.isForbidden) {
          blockedFiles.push(`${file.name} (${nameCheck.reason})`);
          noticeDetails.push({
            fileName: file.name,
            blockedReason: nameCheck.reason,
            status: 'BLOCKED',
            findings: [
              {
                patternId: 'forbidden-filename',
                name: 'Arquivo Bloqueado',
                severity: 'CRITICAL',
                description: nameCheck.reason || 'Tipo de arquivo restrito.',
                matchedPreview: file.name,
                line: 1,
                remediation: 'Não envie arquivos de configuração de ambiente (.env) ou chaves privadas.',
                securityImpact: 'Credentials exposure risk (Master environment keys & private certificates)'
              }
            ]
          });
          return;
        }

        const validation = validateFileForSensitivePatterns(file.name, file.content);
        if (validation.isForbiddenFile || validation.hasBlockers) {
          blockedFiles.push(`${file.name} [${validation.findings.map(f => f.name).join(', ')}]`);
          noticeDetails.push({
            fileName: file.name,
            blockedReason: validation.blockedReason,
            status: 'BLOCKED',
            findings: validation.findings
          });
        } else if (validation.hasWarnings) {
          warningFiles.push(`${file.name} (${validation.findings.length} aviso(s))`);
          noticeDetails.push({
            fileName: file.name,
            status: 'WARNING',
            findings: validation.findings
          });
        } else {
          noticeDetails.push({
            fileName: file.name,
            status: 'VALIDATED',
            findings: []
          });
        }
      });

      if (blockedFiles.length > 0) {
        setValidationNotice({
          type: 'error',
          title: 'Arquivos Sensíveis Bloqueados',
          phase: 'Blocked',
          message: `Violações detectadas durante a re-verificação: ${blockedFiles.join('; ')}`,
          details: noticeDetails.filter(d => d.status === 'BLOCKED')
        });
      } else if (warningFiles.length > 0) {
        setValidationNotice({
          type: 'warning',
          title: 'Varredura com Alertas de Padrões',
          phase: 'Filtered',
          message: `Re-análise concluída com potenciais tokens detectados: ${warningFiles.join('; ')}`,
          details: noticeDetails.filter(d => d.status === 'WARNING')
        });
      } else {
        setValidationNotice({
          type: 'success',
          title: 'Workspace Re-validado com Sucesso',
          phase: 'Validated',
          message: `${files.length} arquivo(s) re-analisado(s) pelo motor de varredura. Nenhuma violação crítica encontrada.`,
          details: noticeDetails
        });
      }
    }

    // Trigger complete scan with engine
    executeScan(files, rules, ignorePatterns);

    // Audit log entry
    const rescanEvent: AuditLogEvent = {
      id: `audit-rescan-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString(),
      type: 'SCAN_START',
      message: `Quick Rescan executado para ${files.length} arquivo(s) ativos no workspace.`,
      severity: 'LOW',
      details: { totalFiles: files.length, action: 'QUICK_RESCAN' }
    };
    setAuditLogs(prev => [rescanEvent, ...prev].slice(0, 80));
  }, [files, rules, ignorePatterns, executeScan]);

  // Handle file uploads with pre-flight security validation
  const handleFileUpload = (uploadedFiles: FileList) => {
    const newScannedFiles: ScannedFile[] = [];
    const blockedFiles: string[] = [];
    const warningFiles: string[] = [];
    const noticeDetails: NoticeDetailItem[] = [];
    const readers: Promise<void>[] = [];

    Array.from(uploadedFiles).forEach((file) => {
      // 1. Immediately check for forbidden file names (.env, .pem, id_rsa, etc.)
      const nameCheck = isForbiddenWorkspaceFile(file.name);
      if (nameCheck.isForbidden) {
        blockedFiles.push(`${file.name} (${nameCheck.reason})`);
        noticeDetails.push({
          fileName: file.name,
          blockedReason: nameCheck.reason,
          status: 'BLOCKED',
          findings: [
            {
              patternId: 'forbidden-filename',
              name: 'Arquivo Bloqueado',
              severity: 'CRITICAL',
              description: nameCheck.reason || 'Tipo de arquivo restrito.',
              matchedPreview: file.name,
              line: 1,
              remediation: 'Não envie arquivos de configuração de ambiente (.env) ou chaves privadas.',
              securityImpact: 'Credentials exposure risk (Master environment keys & private certificates)'
            }
          ]
        });
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
            noticeDetails.push({
              fileName: file.name,
              blockedReason: validation.blockedReason,
              status: 'BLOCKED',
              findings: validation.findings
            });
          } else {
            if (validation.hasWarnings) {
              warningFiles.push(`${file.name} (${validation.findings.length} aviso(s))`);
              noticeDetails.push({
                fileName: file.name,
                status: 'WARNING',
                findings: validation.findings
              });
            } else {
              noticeDetails.push({
                fileName: file.name,
                status: 'VALIDATED',
                findings: []
              });
            }
            const path = (file as any).webkitRelativePath || file.name;
            const ext = file.name.split('.').pop() || '';
            newScannedFiles.push({
              name: file.name,
              path,
              content,
              size: file.size,
              extension: ext,
              lastModified: file.lastModified || Date.now()
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
          phase: 'Blocked',
          message: `Os seguintes arquivos não puderam ser adicionados por conterem variáveis de ambiente (.env) ou chaves privadas críticas: ${blockedFiles.join('; ')}`,
          details: noticeDetails.filter(d => d.status === 'BLOCKED')
        });
      } else if (warningFiles.length > 0) {
        setValidationNotice({
          type: 'warning',
          title: 'Importação com Alertas de Padrões',
          phase: 'Filtered',
          message: `Arquivos importados com potenciais tokens detectados: ${warningFiles.join('; ')}`,
          details: noticeDetails.filter(d => d.status === 'WARNING')
        });
      } else if (newScannedFiles.length > 0) {
        setValidationNotice({
          type: 'success',
          title: 'Importação Segura Concluída',
          phase: 'Validated',
          message: `${newScannedFiles.length} arquivo(s) validado(s) com sucesso e adicionado(s) ao workspace.`,
          details: noticeDetails
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
        phase: 'Blocked',
        message: validation.blockedReason || `Não é permitido adicionar arquivos de ambiente (.env) ou segredos críticos não mascarados (${validation.findings.map(f => f.name).join(', ')}).`,
        details: [{
          fileName: name,
          blockedReason: validation.blockedReason,
          status: 'BLOCKED',
          findings: validation.findings
        }]
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
      phase: 'Validated',
      message: `O arquivo ${name} foi validado e inserido no workspace com sucesso.`,
      details: [{
        fileName: name,
        status: 'VALIDATED',
        findings: []
      }]
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

  // Global Keyboard Shortcuts (Cmd+K, Cmd+S, Cmd+E, Cmd+G, Cmd+I, Cmd+B, Cmd+/, ?, 1-8, Esc)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isCmdOrCtrl = e.metaKey || e.ctrlKey;
      const target = e.target as HTMLElement | null;
      const isInputElement = target && (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT' ||
        target.isContentEditable
      );

      // Cmd+K / Ctrl+K: Toggle Command Palette
      if (isCmdOrCtrl && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setShowCommandPalette(prev => !prev);
        return;
      }

      // Cmd+S / Ctrl+S: Trigger SAST Scan
      if (isCmdOrCtrl && (e.key === 's' || e.key === 'S')) {
        e.preventDefault();
        if (!isScanning) {
          executeScan(files, rules, ignorePatterns);
          setShortcutToast({
            message: 'Análise SAST iniciada via atalho',
            key: isMac ? '⌘S' : 'Ctrl+S'
          });
          setTimeout(() => setShortcutToast(null), 2500);
        }
        return;
      }

      // Cmd+E / Ctrl+E: Open Export Modal
      if (isCmdOrCtrl && (e.key === 'e' || e.key === 'E')) {
        e.preventDefault();
        setShowExportModal(true);
        return;
      }

      // Cmd+G / Ctrl+G: Open Security Glossary
      if (isCmdOrCtrl && (e.key === 'g' || e.key === 'G')) {
        e.preventDefault();
        handleOpenGlossary();
        return;
      }

      // Cmd+I / Ctrl+I: Open Global Ignore List Modal
      if (isCmdOrCtrl && (e.key === 'i' || e.key === 'I')) {
        e.preventDefault();
        setShowIgnoreModal(true);
        return;
      }

      // Cmd+B / Ctrl+B: Reset Demo Workspace
      if (isCmdOrCtrl && (e.key === 'b' || e.key === 'B')) {
        e.preventDefault();
        handleResetWorkspace();
        setShortcutToast({
          message: 'Workspace demo restaurado via atalho',
          key: isMac ? '⌘B' : 'Ctrl+B'
        });
        setTimeout(() => setShortcutToast(null), 2500);
        return;
      }

      // Cmd+/ or Ctrl+/ or ?: Open Keyboard Shortcuts modal
      if ((isCmdOrCtrl && e.key === '/') || (!isInputElement && e.key === '?')) {
        e.preventDefault();
        setShowShortcutsModal(true);
        return;
      }

      // Escape: Close active modals
      if (e.key === 'Escape') {
        if (showCommandPalette) {
          setShowCommandPalette(false);
          return;
        }
        if (showShortcutsModal) {
          setShowShortcutsModal(false);
          return;
        }
        if (showExportModal) {
          setShowExportModal(false);
          return;
        }
        if (showIgnoreModal) {
          setShowIgnoreModal(false);
          return;
        }
        if (showGlossaryModal) {
          setShowGlossaryModal(false);
          return;
        }
        if (showTour) {
          handleCloseTour();
          return;
        }
      }

      // Navigation: 1 through 0, plus -
      const tabMap: Record<string, string> = {
        '1': 'dashboard',
        '2': 'scanner',
        '3': 'endpoints',
        '4': 'jsminer',
        '5': 'dataflow',
        '6': 'frameworks',
        '7': 'securityonion',
        '8': 'crowdstrike',
        '9': 'rules',
        '0': 'cli',
        '-': 'cicd'
      };

      if (!isInputElement && !isCmdOrCtrl && !e.altKey && tabMap[e.key]) {
        setActiveTab(tabMap[e.key]);
      } else if (isCmdOrCtrl && !e.altKey && !e.shiftKey && tabMap[e.key]) {
        e.preventDefault();
        setActiveTab(tabMap[e.key]);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [
    isScanning,
    files,
    rules,
    ignorePatterns,
    showCommandPalette,
    showShortcutsModal,
    showExportModal,
    showIgnoreModal,
    showGlossaryModal,
    showTour,
    executeScan,
    handleResetWorkspace,
    handleCloseTour,
    isMac
  ]);

  return (
    <div className="min-h-screen bg-[#050505] text-[#E0E0E0] flex flex-col font-sans selection:bg-[#FF3E00] selection:text-white relative">
      {/* Global Real-time Scan Progress Bar (0% to 100%) */}
      <GlobalScanProgressBar
        isScanning={isScanning}
        progress={scanProgress}
        onTriggerScan={() => executeScan(files, rules, ignorePatterns)}
      />

      {/* Top Navigation & App Bar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        report={report}
        isScanning={isScanning}
        scanProgress={scanProgress}
        onRunScan={() => executeScan(files, rules, ignorePatterns)}
        onOpenExport={() => setShowExportModal(true)}
        onResetWorkspace={handleResetWorkspace}
        onClearWorkspace={handleClearAllFilesAndValidation}
        onOpenTour={() => setShowTour(true)}
        onOpenIgnoreModal={() => setShowIgnoreModal(true)}
        activeIgnoreCount={ignorePatterns.filter(p => p.enabled).length}
        onOpenGlossary={() => handleOpenGlossary()}
        onOpenCommandPalette={() => setShowCommandPalette(true)}
        onOpenShortcuts={() => setShowShortcutsModal(true)}
      />

      {/* Main Container Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-6 pb-12">
        {/* Workspace Ingestion & Security Validation Banner */}
        {validationNotice && (
          <div 
            id="workspace-validation-notice"
            className={`mb-6 p-3.5 sm:p-4.5 rounded-xl border flex flex-col sm:flex-row sm:items-start justify-between gap-3 sm:gap-4 transition-all duration-200 w-full min-w-0 overflow-hidden ${
              validationNotice.type === 'error'
                ? 'bg-rose-950/40 border-rose-800/60 text-rose-200'
                : validationNotice.type === 'warning'
                ? 'bg-amber-950/40 border-amber-800/60 text-amber-200'
                : 'bg-emerald-950/40 border-emerald-800/60 text-emerald-200'
            }`}
          >
            <div className="flex items-start gap-3 flex-1 min-w-0">
              <div className="shrink-0 mt-0.5 flex items-center justify-center">
                {validationNotice.type === 'error' ? (
                  <ShieldAlert className="w-5 h-5 text-rose-400" />
                ) : validationNotice.type === 'warning' ? (
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                ) : (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="text-sm font-semibold tracking-wide leading-snug">
                    {validationNotice.title}
                  </h4>

                  {/* Dynamic Scan Status / Validation Phase Badge */}
                  {isScanning ? (
                    <span 
                      id="badge-notice-phase-scanning"
                      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider bg-sky-500/20 text-sky-300 border border-sky-400/40 shadow-sm"
                    >
                      <Loader2 className="w-3 h-3 animate-spin text-sky-400" />
                      <span>Analyzing...</span>
                    </span>
                  ) : (
                    <span 
                      id="badge-notice-phase-status"
                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider border shadow-sm ${
                        validationNotice.type === 'error'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : validationNotice.type === 'warning'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${
                        validationNotice.type === 'error'
                          ? 'bg-rose-400'
                          : validationNotice.type === 'warning'
                          ? 'bg-amber-400'
                          : 'bg-emerald-400'
                      }`} />
                      <span>
                        {validationNotice.phase || (
                          validationNotice.type === 'error'
                            ? 'Blocked'
                            : validationNotice.type === 'warning'
                            ? 'Filtered'
                            : 'Validated'
                        )}
                      </span>
                    </span>
                  )}
                </div>

                <div className="text-xs mt-1 leading-relaxed opacity-90 break-words flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span>{validationNotice.message}</span>
                  <button
                    id="btn-toggle-validation-details"
                    onClick={() => setIsNoticeDetailsOpen(prev => !prev)}
                    className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-white/10 hover:bg-white/20 text-white font-mono text-[10.5px] font-bold uppercase tracking-wider transition-all cursor-pointer border border-white/20 hover:border-white/40 shrink-0"
                    title="Exibir/ocultar lista detalhada de regras e achados de validação"
                  >
                    <FileCode className="w-3 h-3 text-white/80" />
                    <span>{isNoticeDetailsOpen ? 'ocultar detalhes' : 'ver detalhes'}</span>
                    {isNoticeDetailsOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                </div>

                {/* Expandable Drawer with Raw Validation Code Findings */}
                {isNoticeDetailsOpen && (
                  <div 
                    id="workspace-validation-details-drawer"
                    className="mt-3 pt-3 border-t border-white/15 w-full space-y-2.5 transition-all animate-in fade-in slide-in-from-top-1 duration-150"
                  >
                    <div className="flex flex-wrap items-center justify-between pb-1 border-b border-white/10 text-[10.5px] font-mono text-white/80 uppercase gap-2">
                      <span className="flex items-center gap-1.5 font-bold">
                        <Terminal className="w-3.5 h-3.5 text-white/70" />
                        Código & Regras de Ingestão Segura
                      </span>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[9.5px] text-white/60 shrink-0">
                          {validationNotice.details?.reduce((acc, d) => acc + (d.findings?.length || (d.blockedReason ? 1 : 0)), 0) || 0} achado(s)
                        </span>
                        <button
                          id="btn-drawer-quick-rescan"
                          type="button"
                          onClick={handleQuickRescan}
                          disabled={isScanning}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-500/20 hover:bg-sky-500/30 text-sky-200 hover:text-sky-100 text-[10px] normal-case transition-colors cursor-pointer border border-sky-500/30 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                          title="Re-executar o motor de varredura no workspace atual"
                        >
                          <RefreshCw className={`w-3 h-3 text-sky-400 ${isScanning ? 'animate-spin' : ''}`} />
                          <span>{isScanning ? 'Scanning...' : 'Quick Rescan'}</span>
                        </button>
                        <div className="relative">
                          <button
                            id="btn-drawer-file-metadata"
                            type="button"
                            onClick={() => setShowFilesMetaPopover(prev => !prev)}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-200 hover:text-indigo-100 text-[10px] normal-case transition-colors cursor-pointer border border-indigo-500/30 shadow-sm"
                            title="Exibir metadados dos arquivos do workspace"
                          >
                            <FileText className="w-3 h-3 text-indigo-400" />
                            <span>Metadata</span>
                          </button>
                          {showFilesMetaPopover && !validationNotice && (
                            <WorkspaceFilesMetaPopover
                              files={files}
                              isOpen={showFilesMetaPopover}
                              onClose={() => setShowFilesMetaPopover(false)}
                              onSelectFile={(f) => {
                                setSelectedFile(f);
                                setActiveTab('scanner');
                                setShowFilesMetaPopover(false);
                              }}
                              onBatchQuickIgnore={handleBatchQuickIgnore}
                              onBatchDeleteFiles={handleBatchDeleteFiles}
                              previousWorkspaceSize={previousWorkspaceSize}
                            />
                          )}
                        </div>
                        <button
                          id="btn-drawer-copy-log"
                          type="button"
                          onClick={handleCopyFindingsLog}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-white/10 hover:bg-white/20 text-white text-[10px] normal-case transition-colors cursor-pointer border border-white/20 shadow-sm"
                          title="Copiar lista de achados para a área de transferência"
                        >
                          {isLogCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-white/80" />}
                          <span>{isLogCopied ? 'Copiado!' : 'Copy Log'}</span>
                        </button>
                        <button
                          id="btn-drawer-clear-all"
                          type="button"
                          onClick={handleClearAllFilesAndValidation}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 hover:text-rose-100 text-[10px] normal-case transition-colors cursor-pointer border border-rose-500/30 shadow-sm"
                          title="Remover todos os arquivos atuais e redefinir validação"
                        >
                          <Trash2 className="w-3 h-3 text-rose-400" />
                          <span>Clear All</span>
                        </button>
                      </div>
                    </div>

                    {/* Compact Recharts Donut Chart Visualizing Finding Severities Distribution & Sparkline Trend */}
                    <ValidationSeverityDonutChart
                      distribution={noticeSeverityDistribution}
                      onSelectSeverity={(sev) => toggleNoticeSeverityFilter(sev)}
                      activeFilters={noticeSeverityFilters}
                      fileSetKey={files.map(f => f.name).sort().join('_') || 'empty_workspace'}
                      riskScore={report.metrics.riskScore}
                    />

                    {/* Severity Filter Toggle Controls */}
                    <div 
                      id="workspace-validation-severity-filters"
                      className="flex flex-wrap items-center justify-between gap-2 p-1.5 rounded bg-black/40 border border-white/10 text-[10px] font-mono"
                    >
                      <div className="flex items-center gap-1.5 text-white/70">
                        <Filter className="w-3 h-3 text-white/60" />
                        <span className="font-bold uppercase tracking-wider text-[9.5px]">Filtro de Severidade:</span>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5">
                        {/* Critical toggle with Explanatory Tooltip */}
                        <SeverityTooltip
                          severity="CRITICAL"
                          count={noticeSeverityDistribution.critical}
                          isActive={noticeSeverityFilters.CRITICAL}
                          remediationTime={
                            secScanConfig.dynamicMttrCalculation !== false
                              ? calculateDynamicRemediationTime('CRITICAL', noticeSeverityDistribution.critical, secScanConfig)
                              : (secScanConfig.severityConfig.CRITICAL.remediationTime || secScanConfig.remediationTime.CRITICAL)
                          }
                          config={secScanConfig}
                          align="left"
                          position="bottom"
                        >
                          <button
                            id="btn-filter-severity-critical"
                            type="button"
                            onClick={() => toggleNoticeSeverityFilter('CRITICAL')}
                            className={`px-2 py-0.5 rounded inline-flex items-center gap-1 font-mono text-[10px] font-bold uppercase tracking-wider transition-all border cursor-pointer ${
                              noticeSeverityFilters.CRITICAL
                                ? 'bg-rose-500/25 text-rose-200 border-rose-500/50 shadow-sm'
                                : 'bg-black/30 text-zinc-500 border-white/10 hover:text-rose-300 hover:border-rose-500/30 opacity-60'
                            }`}
                            title="Alternar exibição de achados Críticos (passe o mouse para ver detalhes de MTTR)"
                            aria-pressed={noticeSeverityFilters.CRITICAL}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${noticeSeverityFilters.CRITICAL ? 'bg-rose-500' : 'bg-zinc-600'}`} />
                            <span>Crítico</span>
                            <span className="text-[9px] opacity-75">({noticeSeverityDistribution.critical})</span>
                          </button>
                        </SeverityTooltip>

                        {/* High toggle with Explanatory Tooltip */}
                        <SeverityTooltip
                          severity="HIGH"
                          count={noticeSeverityDistribution.high}
                          isActive={noticeSeverityFilters.HIGH}
                          remediationTime={
                            secScanConfig.dynamicMttrCalculation !== false
                              ? calculateDynamicRemediationTime('HIGH', noticeSeverityDistribution.high, secScanConfig)
                              : (secScanConfig.severityConfig.HIGH.remediationTime || secScanConfig.remediationTime.HIGH)
                          }
                          config={secScanConfig}
                          align="center"
                          position="bottom"
                        >
                          <button
                            id="btn-filter-severity-high"
                            type="button"
                            onClick={() => toggleNoticeSeverityFilter('HIGH')}
                            className={`px-2 py-0.5 rounded inline-flex items-center gap-1 font-mono text-[10px] font-bold uppercase tracking-wider transition-all border cursor-pointer ${
                              noticeSeverityFilters.HIGH
                                ? 'bg-amber-500/25 text-amber-200 border-amber-500/50 shadow-sm'
                                : 'bg-black/30 text-zinc-500 border-white/10 hover:text-amber-300 hover:border-amber-500/30 opacity-60'
                            }`}
                            title="Alternar exibição de achados Altos (passe o mouse para ver detalhes de MTTR)"
                            aria-pressed={noticeSeverityFilters.HIGH}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${noticeSeverityFilters.HIGH ? 'bg-amber-500' : 'bg-zinc-600'}`} />
                            <span>Alto</span>
                            <span className="text-[9px] opacity-75">({noticeSeverityDistribution.high})</span>
                          </button>
                        </SeverityTooltip>

                        {/* Warning toggle with Explanatory Tooltip */}
                        <SeverityTooltip
                          severity="WARNING"
                          count={noticeSeverityDistribution.warning}
                          isActive={noticeSeverityFilters.WARNING}
                          remediationTime={
                            secScanConfig.dynamicMttrCalculation !== false
                              ? calculateDynamicRemediationTime('WARNING', noticeSeverityDistribution.warning, secScanConfig)
                              : (secScanConfig.severityConfig.WARNING.remediationTime || secScanConfig.remediationTime.WARNING)
                          }
                          config={secScanConfig}
                          align="right"
                          position="bottom"
                        >
                          <button
                            id="btn-filter-severity-warning"
                            type="button"
                            onClick={() => toggleNoticeSeverityFilter('WARNING')}
                            className={`px-2 py-0.5 rounded inline-flex items-center gap-1 font-mono text-[10px] font-bold uppercase tracking-wider transition-all border cursor-pointer ${
                              noticeSeverityFilters.WARNING
                                ? 'bg-yellow-500/25 text-yellow-200 border-yellow-500/50 shadow-sm'
                                : 'bg-black/30 text-zinc-500 border-white/10 hover:text-yellow-300 hover:border-yellow-500/30 opacity-60'
                            }`}
                            title="Alternar exibição de achados de Aviso (passe o mouse para ver detalhes de MTTR)"
                            aria-pressed={noticeSeverityFilters.WARNING}
                          >
                            <span className={`w-1.5 h-1.5 rounded-full ${noticeSeverityFilters.WARNING ? 'bg-yellow-400' : 'bg-zinc-600'}`} />
                            <span>Aviso</span>
                            <span className="text-[9px] opacity-75">({noticeSeverityDistribution.warning})</span>
                          </button>
                        </SeverityTooltip>

                        {/* Quick reset/show all if any is toggled off */}
                        {(!noticeSeverityFilters.CRITICAL || !noticeSeverityFilters.HIGH || !noticeSeverityFilters.WARNING) && (
                          <button
                            id="btn-filter-severity-reset"
                            type="button"
                            onClick={resetNoticeSeverityFilters}
                            className="px-1.5 py-0.5 rounded text-[9.5px] font-mono text-zinc-400 hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-colors cursor-pointer"
                            title="Mostrar todas as severidades"
                          >
                            Mostrar Todos
                          </button>
                        )}

                        {/* Direct MTTR Global Config modal trigger button with visual alert marking */}
                        <button
                          id="btn-configure-mttr-remediation"
                          type="button"
                          onClick={() => setShowMttrConfigModal(true)}
                          className={`px-1.5 py-0.5 rounded text-[9.5px] font-mono transition-all cursor-pointer inline-flex items-center gap-1 border ${
                            isWorkspaceMttrExceeded
                              ? 'bg-rose-500/25 text-rose-200 border-rose-500/50 hover:bg-rose-500/35 ring-1 ring-rose-500/40 shadow-xs'
                              : 'text-zinc-400 hover:text-white bg-white/5 hover:bg-white/10 border-white/10'
                          }`}
                          title={
                            isWorkspaceMttrExceeded
                              ? `ALERTA DE SLA: MTTR médio atual (${workspaceCurrentMttrHours}h) excede o limite máximo permitido de ${maxAllowedMttrLimit}h configurado no SecScanMttrConfigModal! Clique para ajustar.`
                              : "Ajustar parâmetros de remediationTime (MTTR) no objeto de configuração global do SecScan"
                          }
                        >
                          {isWorkspaceMttrExceeded ? (
                            <AlertTriangle className="w-2.5 h-2.5 text-rose-400 shrink-0 animate-bounce" />
                          ) : (
                            <Clock className="w-2.5 h-2.5 text-zinc-400" />
                          )}
                          <span>MTTR Config</span>
                          {isWorkspaceMttrExceeded && (
                            <span className="px-1 py-0.2 rounded bg-rose-600/80 text-[8px] text-white font-extrabold uppercase tracking-tight">
                              &gt;{maxAllowedMttrLimit}h
                            </span>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Mini Trendline Chart displaying Historical Evolution of Average Remediation Time across last 5 scans */}
                    <MttrMiniTrendlineChart
                      distribution={noticeSeverityDistribution}
                      config={secScanConfig}
                      fileSetKey={files.map(f => f.name).sort().join('_') || 'empty_workspace'}
                      onOpenMttrConfig={() => setShowMttrConfigModal(true)}
                    />

                    {!noticeSeverityFilters.CRITICAL && !noticeSeverityFilters.HIGH && !noticeSeverityFilters.WARNING ? (
                      <div className="p-3 rounded bg-black/50 border border-white/10 text-center space-y-1 font-mono text-xs text-white/70">
                        <p>Nenhum nível de severidade selecionado nos filtros.</p>
                        <button
                          id="btn-filter-severity-enable-all"
                          type="button"
                          onClick={resetNoticeSeverityFilters}
                          className="text-sky-300 hover:underline text-[11px] cursor-pointer"
                        >
                          Ativar todos os filtros de severidade
                        </button>
                      </div>
                    ) : filteredNoticeDetails && filteredNoticeDetails.length > 0 ? (
                      <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                        {filteredNoticeDetails.map((detail, dIdx) => (
                          <div 
                            key={`detail-${dIdx}`}
                            className="p-2.5 rounded bg-black/50 border border-white/10 space-y-2 text-xs font-mono"
                          >
                            {/* File Header */}
                            <div className="flex flex-wrap items-center justify-between gap-1.5 pb-1 border-b border-white/10">
                              <div className="flex items-center gap-1.5 font-bold text-white">
                                <FileCode className="w-3.5 h-3.5 text-white/70" />
                                <span>{detail.fileName}</span>
                              </div>
                              <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase tracking-wider ${
                                detail.status === 'BLOCKED'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                  : detail.status === 'WARNING'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                              }`}>
                                {detail.status}
                              </span>
                            </div>

                            {/* Blocked Reason Policy */}
                            {detail.showBlockedPolicy && detail.blockedReason && (
                              <div className="text-[10.5px] text-rose-300 bg-rose-950/40 p-2 rounded border border-rose-800/40 space-y-1">
                                <div className="font-bold uppercase tracking-wider flex items-center gap-1 text-[10px]">
                                  <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0" />
                                  <span>Regra de Política: Arquivo Proibido</span>
                                </div>
                                <p className="opacity-90 leading-relaxed break-words">{detail.blockedReason}</p>
                                <div 
                                  id={`drawer-policy-impact-${dIdx}`}
                                  className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[9.5px] font-mono border bg-rose-950/50 text-rose-200 border-rose-500/40 w-fit"
                                  title="Security Impact: Risco de exposição de chaves mestras e arquivos de ambiente"
                                >
                                  <ShieldAlert className="w-3 h-3 text-rose-400 shrink-0" />
                                  <span className="font-bold uppercase tracking-wider text-[8.5px] opacity-80">Security Impact:</span>
                                  <span className="font-semibold text-white/95">Credentials exposure risk (Master environment keys & private certificates)</span>
                                </div>
                              </div>
                            )}

                            {/* Findings List */}
                            {detail.visibleFindings && detail.visibleFindings.length > 0 ? (
                              <div className="space-y-1.5 pt-0.5">
                                {detail.visibleFindings.map((f, fIdx) => (
                                  <div 
                                    key={`finding-${fIdx}`}
                                    id={`validation-finding-card-${fIdx}`}
                                    className="p-2 rounded bg-black/60 border border-white/10 space-y-1.5"
                                  >
                                    <div className="flex flex-wrap items-center justify-between gap-1.5">
                                      <span className="font-bold text-white flex items-center gap-1.5">
                                        <span className={`w-1.5 h-1.5 rounded-full ${
                                          f.severity === 'CRITICAL' ? 'bg-rose-500' : f.severity === 'HIGH' ? 'bg-amber-500' : 'bg-yellow-500'
                                        }`} />
                                        <span>{f.name}</span>
                                        <span className="text-[9.5px] text-white/50 font-normal">[{f.patternId}]</span>
                                      </span>
                                      <span className="text-[9.5px] text-white/60">Linha {f.line}</span>
                                    </div>

                                    {/* Security Impact Indicator */}
                                    <div 
                                      id={`validation-finding-impact-${fIdx}`}
                                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[9.5px] font-mono border ${
                                        f.severity === 'CRITICAL'
                                          ? 'bg-rose-950/50 text-rose-200 border-rose-500/40'
                                          : f.severity === 'HIGH'
                                          ? 'bg-amber-950/50 text-amber-200 border-amber-500/40'
                                          : 'bg-yellow-950/50 text-yellow-200 border-yellow-500/40'
                                      }`}
                                      title="Security Impact: Motivo pelo qual este padrão foi sinalizado"
                                    >
                                      <ShieldAlert className={`w-3 h-3 shrink-0 ${
                                        f.severity === 'CRITICAL' ? 'text-rose-400' : f.severity === 'HIGH' ? 'text-amber-400' : 'text-yellow-400'
                                      }`} />
                                      <span className="font-bold uppercase tracking-wider text-[8.5px] opacity-80">Security Impact:</span>
                                      <span className="font-semibold text-white/95">{f.securityImpact || resolveSecurityImpact(f)}</span>
                                    </div>

                                    <p className="text-[10.5px] text-white/80 leading-snug">{f.description}</p>

                                    {/* Code preview snippet with syntax highlighter */}
                                    {f.matchedPreview && (
                                      <SnippetHighlighter
                                        code={f.matchedPreview}
                                        line={f.line}
                                        severity={f.severity}
                                      />
                                    )}

                                    {/* Remediation guidance */}
                                    {f.remediation && (
                                      <div className="text-[9.5px] text-emerald-300/90 flex items-start gap-1">
                                        <span className="font-bold uppercase text-[8.5px] px-1 bg-emerald-950/50 rounded border border-emerald-800/40 shrink-0">Correção:</span>
                                        <span className="leading-tight">{f.remediation}</span>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : null}

                            {/* Note when findings are filtered out */}
                            {detail.hiddenByFilterCount > 0 && (
                              <div className="text-[10px] text-zinc-400 italic flex items-center gap-1 pt-1">
                                <Filter className="w-2.5 h-2.5 text-zinc-500" />
                                <span>{detail.hiddenByFilterCount} achado(s) oculto(s) pelo filtro de severidade ativo.</span>
                              </div>
                            )}

                            {/* Clean File indicator */}
                            {detail.isCleanFile && (
                              <div className="text-[10.5px] text-emerald-300 flex items-center gap-1.5">
                                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                                <span>Nenhum segredo ou token sensível detectado no arquivo.</span>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-2.5 rounded bg-black/50 border border-white/10 text-xs font-mono text-white/80 space-y-1">
                        <div className="text-[10.5px] text-white font-bold flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Pre-Flight Ingestion: Nenhuma violação detectada</span>
                        </div>
                        <p className="text-[10px] opacity-75 leading-relaxed">
                          O arquivo passou pelas verificações de extensões proibidas (.env, .pem, chaves privadas) e análise de padrões de segredos em texto claro.
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
            <div className="flex items-center gap-1.5 self-end sm:self-start shrink-0 flex-wrap justify-end">
              <button
                id="btn-validation-quick-rescan"
                type="button"
                onClick={handleQuickRescan}
                disabled={isScanning}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 text-sky-200 hover:text-sky-100 font-mono text-[11px] font-semibold transition-colors cursor-pointer border border-sky-500/30 hover:border-sky-500/50 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
                title="Re-executar o motor de varredura no workspace atual sem recarregar a página"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-sky-400 ${isScanning ? 'animate-spin' : ''}`} />
                <span>{isScanning ? 'Scanning...' : 'Quick Rescan'}</span>
              </button>

              <div className="relative">
                <button
                  id="btn-validation-file-metadata"
                  type="button"
                  onClick={() => setShowFilesMetaPopover(prev => !prev)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-200 hover:text-indigo-100 font-mono text-[11px] font-semibold transition-colors cursor-pointer border border-indigo-500/30 hover:border-indigo-500/50 shadow-sm"
                  title="Exibir metadados dos arquivos do workspace (linhas de código, tamanho em KB e data de modificação)"
                >
                  <FileText className="w-3.5 h-3.5 text-indigo-400" />
                  <span>File Metadata</span>
                  <span className="px-1.5 py-0.2 rounded bg-indigo-400/20 text-indigo-300 text-[9.5px]">
                    {files.length}
                  </span>
                </button>

                <WorkspaceFilesMetaPopover
                  files={files}
                  isOpen={showFilesMetaPopover}
                  onClose={() => setShowFilesMetaPopover(false)}
                  onSelectFile={(f) => {
                    setSelectedFile(f);
                    setActiveTab('scanner');
                    setShowFilesMetaPopover(false);
                  }}
                  onBatchQuickIgnore={handleBatchQuickIgnore}
                  onBatchDeleteFiles={handleBatchDeleteFiles}
                  previousWorkspaceSize={previousWorkspaceSize}
                />
              </div>

              <button
                id="btn-validation-copy-log"
                type="button"
                onClick={handleCopyFindingsLog}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-white font-mono text-[11px] font-semibold transition-colors cursor-pointer border border-white/20 hover:border-white/40 shadow-sm"
                title="Copiar lista completa de achados para a área de transferência"
              >
                {isLogCopied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-emerald-300">Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-white/80" />
                    <span>Copy Log</span>
                  </>
                )}
              </button>

              <button
                id="btn-validation-clear-all"
                type="button"
                onClick={handleClearAllFilesAndValidation}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 hover:text-rose-100 font-mono text-[11px] font-semibold transition-colors cursor-pointer border border-rose-500/30 hover:border-rose-500/50 shadow-sm"
                title="Remover todos os arquivos atuais e redefinir o estado de validação"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                <span>Clear All</span>
              </button>

              <button
                id="btn-dismiss-validation-notice"
                onClick={() => setValidationNotice(null)}
                className="p-1.5 rounded-lg hover:bg-white/10 text-white/70 hover:text-white transition-colors cursor-pointer flex items-center justify-center"
                title="Fechar aviso"
                aria-label="Fechar aviso"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
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
            onApplyFix={handleApplyFix}
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
            onNavigateToDataFlow={() => setActiveTab('dataflow')}
          />
        )}

        {activeTab === 'dataflow' && (
          <DataFlowGraphView
            graphData={report.dataFlowGraph}
            files={files}
            onSelectFile={(filePath) => {
              const target = files.find(f => f.path === filePath);
              if (target) {
                setSelectedFile(target);
                setActiveTab('scanner');
              }
            }}
          />
        )}

        {activeTab === 'frameworks' && (
          <SecurityFrameworksHub
            report={report}
            onSelectFinding={handleSelectFinding}
            onNavigateToScanner={() => setActiveTab('scanner')}
          />
        )}

        {activeTab === 'securityonion' && (
          <SecurityOnionSocView
            report={report}
            onSelectFinding={handleSelectFinding}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToEndpoints={() => setActiveTab('endpoints')}
            onNavigateToDataFlow={() => setActiveTab('dataflow')}
          />
        )}

        {activeTab === 'crowdstrike' && (
          <CrowdStrikeSuiteView
            report={report}
            onSelectFinding={handleSelectFinding}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToDataFlow={() => setActiveTab('dataflow')}
          />
        )}

        {activeTab === 'nmap' && (
          <NmapNetworkSuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToEndpoints={() => setActiveTab('endpoints')}
          />
        )}

        {activeTab === 'nikto' && (
          <NiktoWebScannerView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToEndpoints={() => setActiveTab('endpoints')}
          />
        )}

        {activeTab === 'ngfw' && (
          <NgfwSuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToEndpoints={() => setActiveTab('endpoints')}
            onNavigateToSecurityOnion={() => setActiveTab('securityonion')}
          />
        )}

        {activeTab === 'edr' && (
          <EdrSuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToSecurityOnion={() => setActiveTab('securityonion')}
            onNavigateToNgfw={() => setActiveTab('ngfw')}
          />
        )}

        {activeTab === 'idsips' && (
          <IdsIpsSuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToSecurityOnion={() => setActiveTab('securityonion')}
            onNavigateToNgfw={() => setActiveTab('ngfw')}
            onNavigateToEdr={() => setActiveTab('edr')}
          />
        )}

        {activeTab === 'dnssec' && (
          <DnsSecuritySuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToSecurityOnion={() => setActiveTab('securityonion')}
            onNavigateToNgfw={() => setActiveTab('ngfw')}
            onNavigateToIdsIps={() => setActiveTab('idsips')}
          />
        )}

        {activeTab === 'waf' && (
          <WafSuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToSecurityOnion={() => setActiveTab('securityonion')}
            onNavigateToNgfw={() => setActiveTab('ngfw')}
            onNavigateToIdsIps={() => setActiveTab('idsips')}
            onNavigateToDns={() => setActiveTab('dnssec')}
          />
        )}

        {activeTab === 'sdwan' && (
          <SdwanSuiteView
            report={report}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToNgfw={() => setActiveTab('ngfw')}
            onNavigateToIdsIps={() => setActiveTab('idsips')}
            onNavigateToWaf={() => setActiveTab('waf')}
            onNavigateToDns={() => setActiveTab('dnssec')}
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
            rules={rules}
            ignorePatterns={ignorePatterns}
          />
        )}
      </main>

      {/* Footer Status Bar with Shortcuts Bar */}
      <footer className="border-t border-[#1F1F1F] bg-[#0A0A0A] py-3 px-4 sm:px-8 text-[11px] font-mono text-[#666] flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-3.5 flex-wrap">
          <span className="flex items-center gap-1.5 text-white font-bold">
            <span className="w-2 h-2 rounded-none bg-[#00FF41] inline-block animate-pulse"></span>
            SECSCAN_ENGINE // OPERATIONAL
          </span>
          <span className="text-[#444]">|</span>
          <span>RULES_V4_LOADED: {rules.length}</span>
          <span className="text-[#444] hidden sm:inline">|</span>
          <span className="hidden sm:inline">IGNORE_PATTERNS: {ignorePatterns.filter(p => p.enabled).length} ATIVOS</span>
          <span className="text-[#444] hidden md:inline">|</span>
          <button
            type="button"
            onClick={() => setShowCommandPalette(true)}
            className="hidden md:inline-flex items-center gap-1.5 text-zinc-400 hover:text-white transition-colors cursor-pointer"
            title={`Abrir Command Palette (${isMac ? '⌘K' : 'Ctrl+K'})`}
          >
            <kbd className="px-1.5 py-0.2 rounded bg-[#181818] border border-[#333] text-zinc-300 font-bold text-[9.5px]">
              {isMac ? '⌘K' : 'Ctrl+K'}
            </kbd>
            <span>Comandos</span>
          </button>
          <span className="text-[#444] hidden md:inline">•</span>
          <button
            type="button"
            onClick={() => setShowShortcutsModal(true)}
            className="hidden md:inline-flex items-center gap-1.5 text-zinc-400 hover:text-white transition-colors cursor-pointer"
            title={`Ver atalhos globais (${isMac ? '⌘/' : 'Ctrl+/'} ou ?)`}
          >
            <kbd className="px-1.5 py-0.2 rounded bg-[#181818] border border-[#333] text-zinc-300 font-bold text-[9.5px]">
              ?
            </kbd>
            <span>Atalhos</span>
          </button>
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

      {/* Welcome & Workspace Mode Selection Modal */}
      <WelcomeWorkspaceModal
        isOpen={showWelcomeModal}
        onExploreWithMock={handleExploreWithMock}
        onStartCleanWorkspace={handleStartCleanWorkspace}
        onClose={handleStartCleanWorkspace}
      />

      {/* Quick Tour Modal */}
      <QuickTourModal
        isOpen={showTour && !showWelcomeModal}
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

      {/* Command Palette Modal */}
      <CommandPaletteModal
        isOpen={showCommandPalette}
        onClose={() => setShowCommandPalette(false)}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onRunScan={() => executeScan(files, rules, ignorePatterns)}
        onOpenExport={() => setShowExportModal(true)}
        onOpenIgnoreModal={() => setShowIgnoreModal(true)}
        onOpenGlossary={() => handleOpenGlossary()}
        onOpenTour={() => setShowTour(true)}
        onOpenWelcomeModal={() => setShowWelcomeModal(true)}
        onResetWorkspace={handleResetWorkspace}
        onClearWorkspace={handleClearAllFilesAndValidation}
        onOpenShortcuts={() => setShowShortcutsModal(true)}
        files={files}
        onSelectFile={(f) => {
          setSelectedFile(f);
          setActiveTab('scanner');
        }}
        rules={rules}
        report={report}
        isScanning={isScanning}
      />

      {/* Keyboard Shortcuts Reference Modal */}
      <KeyboardShortcutsModal
        isOpen={showShortcutsModal}
        onClose={() => setShowShortcutsModal(false)}
        onOpenCommandPalette={() => {
          setShowShortcutsModal(false);
          setShowCommandPalette(true);
        }}
      />

      {/* Global SecScan MTTR Configuration Modal */}
      <SecScanMttrConfigModal
        isOpen={showMttrConfigModal}
        onClose={() => setShowMttrConfigModal(false)}
        config={secScanConfig}
        onUpdateConfig={setSecScanConfig}
      />

      {/* Non-intrusive Shortcut Toast Feedback */}
      {shortcutToast && (
        <div
          id="shortcut-toast-feedback"
          className="fixed bottom-14 right-6 z-50 bg-[#0F0F0F] border border-[#00FF41]/50 shadow-[0_0_24px_rgba(0,255,65,0.25)] px-4 py-2.5 rounded-lg flex items-center gap-3 font-mono text-xs text-white animate-in fade-in slide-in-from-bottom-2 duration-150"
        >
          <span className="w-2 h-2 rounded-full bg-[#00FF41] animate-ping" />
          <span className="font-medium">{shortcutToast.message}</span>
          {shortcutToast.key && (
            <kbd className="px-2 py-0.5 rounded bg-[#1B1B1B] border border-[#333] text-[#00FF41] font-bold text-[11px]">
              {shortcutToast.key}
            </kbd>
          )}
        </div>
      )}
    </div>
  );
}
