import { jsPDF } from 'jspdf';
import { ScanReport, SeverityLevel, ScanFinding } from '../types';

export interface PdfReportOptions {
  projectName?: string;
  organizationName?: string;
  author?: string;
}

export function generateSecurityReportPdf(
  report: ScanReport,
  options?: PdfReportOptions
): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const marginX = 14;
  const contentWidth = pageWidth - marginX * 2; // 182 mm
  let currentY = 14;

  const primaryDark = [15, 15, 15]; // #0F0F0F
  const accentRed = [255, 62, 0];    // #FF3E00
  const textDark = [30, 30, 30];
  const textMuted = [100, 100, 100];
  const borderGray = [220, 220, 220];

  const getSeverityColors = (severity: SeverityLevel) => {
    switch (severity) {
      case 'CRITICAL':
        return { bg: [255, 235, 230], text: [211, 47, 47], border: [255, 138, 128] };
      case 'HIGH':
        return { bg: [255, 243, 224], text: [230, 81, 0], border: [255, 183, 77] };
      case 'MEDIUM':
        return { bg: [254, 249, 195], text: [161, 98, 7], border: [253, 224, 71] };
      case 'LOW':
        return { bg: [239, 246, 255], text: [29, 78, 216], border: [147, 197, 253] };
      default:
        return { bg: [243, 244, 246], text: [75, 85, 99], border: [209, 213, 219] };
    }
  };

  const checkPageBreak = (neededHeight: number) => {
    if (currentY + neededHeight > pageHeight - 18) {
      doc.addPage();
      currentY = 16;
      drawPageHeader();
    }
  };

  const drawPageHeader = () => {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text('SECSCAN.JS // RELATÓRIO EXECUTIVO DE AUDITORIA SAST & VULNERABILIDADES', marginX, 10);
    
    doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
    doc.setLineWidth(0.2);
    doc.line(marginX, 12, marginX + contentWidth, 12);
  };

  // ==========================================
  // 1. COVER / HERO BANNER (Página 1)
  // ==========================================
  // Header background box
  doc.setFillColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.rect(marginX, currentY, contentWidth, 38, 'F');

  // Red accent top bar
  doc.setFillColor(accentRed[0], accentRed[1], accentRed[2]);
  doc.rect(marginX, currentY, contentWidth, 2, 'F');

  // Title & Metadata inside Banner
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(accentRed[0], accentRed[1], accentRed[2]);
  doc.text('STATIC APPLICATION SECURITY TESTING • EXECUTIVE RISK REPORT', marginX + 6, currentY + 9);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('AUDITORIA DE SEGURANÇA & EXPOSIÇÃO DE DADOS', marginX + 6, currentY + 18);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(200, 200, 200);
  const orgName = options?.organizationName || 'SecScan Security Engineering';
  const targetRepo = report.target || 'Workspace Root';
  doc.text(`Repositório: ${targetRepo}   •   Emissão: ${new Date(report.timestamp).toLocaleString('pt-BR')} UTC`, marginX + 6, currentY + 26);
  doc.text(`Organização: ${orgName}   •   Engine: SecScan SAST v1.0 (RegEx + Entropy Analysis)`, marginX + 6, currentY + 32);

  currentY += 44;

  // ==========================================
  // 2. EXECUTIVE RISK SUMMARY CARDS
  // ==========================================
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.text('1. SUMÁRIO EXECUTIVO DE RISCO', marginX, currentY);

  currentY += 4;

  // Draw 4 KPI summary cards
  const cardWidth = (contentWidth - 9) / 4;
  const cardHeight = 24;

  const kpis = [
    {
      title: 'SECURITY IMPACT',
      value: `${report.metrics.securityImpactScore ?? 0} / 100`,
      sub: `Nível: ${report.metrics.impactLevel ?? 'NOMINAL'}`,
      isAlert: (report.metrics.securityImpactScore ?? 0) >= 60
    },
    {
      title: 'COMPLIANCE SCORE',
      value: `${report.metrics.securityScore}%`,
      sub: report.metrics.criticalCount === 0 ? 'Conforme com OWASP' : 'Não Conforme',
      isAlert: report.metrics.securityScore < 70
    },
    {
      title: 'TOTAL ACHADOS',
      value: `${report.findings.length}`,
      sub: `${report.metrics.criticalCount} Críticos • ${report.metrics.highCount} Altos`,
      isAlert: report.metrics.criticalCount > 0
    },
    {
      title: 'ARQUIVOS AUDITADOS',
      value: `${report.scannedFilesCount}`,
      sub: `${report.ignoredFilesCount} ignorados (node_modules)`,
      isAlert: false
    }
  ];

  kpis.forEach((kpi, idx) => {
    const x = marginX + idx * (cardWidth + 3);
    doc.setFillColor(250, 250, 250);
    doc.rect(x, currentY, cardWidth, cardHeight, 'F');
    doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
    doc.setLineWidth(0.3);
    doc.rect(x, currentY, cardWidth, cardHeight, 'S');

    // Indicator top edge
    if (kpi.isAlert) {
      doc.setFillColor(accentRed[0], accentRed[1], accentRed[2]);
      doc.rect(x, currentY, cardWidth, 1.5, 'F');
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text(kpi.title, x + 3.5, currentY + 6);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    if (kpi.isAlert) {
      doc.setTextColor(accentRed[0], accentRed[1], accentRed[2]);
    } else {
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
    }
    doc.text(kpi.value, x + 3.5, currentY + 14);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text(kpi.sub, x + 3.5, currentY + 20);
  });

  currentY += cardHeight + 6;

  // Executive Diagnostic Statement Paragraph
  doc.setFillColor(245, 247, 250);
  doc.rect(marginX, currentY, contentWidth, 24, 'F');
  doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
  doc.rect(marginX, currentY, contentWidth, 24, 'S');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.text('DIAGNÓSTICO E POSTURA DE SEGURANÇA:', marginX + 4, currentY + 5.5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(60, 60, 60);

  const hasCriticals = report.metrics.criticalCount > 0;
  const diagnosticText = hasCriticals
    ? `A auditoria identificou ${report.metrics.criticalCount} vulnerabilidade(s) de severidade CRÍTICA e ${report.metrics.highCount} de severidade ALTA. Foram constatadas credenciais de nuvem ativas, tokens privados ou chaves criptográficas em arquivos de alta criticidade (ex: arquivos .env e controladores de backend). Este cenário viola diretrizes de conformidade OWASP Top 10 (A07:2021) e normativas como LGPD e PCI-DSS v4.0. É requerida remediação imediata antes de qualquer deploy em produção.`
    : `O repositório apresenta postura de segurança regular sem achados críticos ativos. Não foram detectadas chaves de produção hardcoded ou credenciais de nuvem em claro. Mantenha os filtros estritos de dependência (node_modules) e a verificação contínua no pipeline de CI/CD para assegurar que segredos futuros não sejam inseridos.`;

  const splitDiagnostic = doc.splitTextToSize(diagnosticText, contentWidth - 8);
  doc.text(splitDiagnostic, marginX + 4, currentY + 10);

  currentY += 30;

  // ==========================================
  // 3. SEVERITY & ENTROPY BREAKDOWN
  // ==========================================
  checkPageBreak(38);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.text('2. DISTRIBUIÇÃO DE ACHADOS POR GRAVIDADE', marginX, currentY);
  currentY += 4;

  const severityStats = [
    { label: 'CRÍTICA', count: report.metrics.criticalCount, points: 25, color: [211, 47, 47], desc: 'Chaves AWS, Private Keys, Senhas em .env' },
    { label: 'ALTA', count: report.metrics.highCount, points: 14, color: [230, 81, 0], desc: 'Tokens JWT, Stripe, GitHub PAT, Google API' },
    { label: 'MÉDIA', count: report.metrics.mediumCount, points: 7, color: [161, 98, 7], desc: 'Database URIs genéricas, endpoints sensíveis' },
    { label: 'BAIXA / INFO', count: report.metrics.lowCount + report.metrics.infoCount, points: 3, color: [29, 78, 216], desc: 'Configurações de teste e avisos estruturais' },
  ];

  // Table header
  doc.setFillColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.rect(marginX, currentY, contentWidth, 6, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7);
  doc.setTextColor(255, 255, 255);
  doc.text('SEVERIDADE', marginX + 4, currentY + 4.2);
  doc.text('QUANTIDADE', marginX + 40, currentY + 4.2);
  doc.text('PESO DE RISCO', marginX + 75, currentY + 4.2);
  doc.text('EXEMPLOS DE VULNERABILIDADE TÍPICA', marginX + 115, currentY + 4.2);

  currentY += 6;

  severityStats.forEach((stat, i) => {
    const isEven = i % 2 === 0;
    doc.setFillColor(isEven ? 255 : 248, isEven ? 255 : 248, isEven ? 255 : 248);
    doc.rect(marginX, currentY, contentWidth, 6, 'F');
    doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
    doc.setLineWidth(0.2);
    doc.line(marginX, currentY + 6, marginX + contentWidth, currentY + 6);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(stat.color[0], stat.color[1], stat.color[2]);
    doc.text(stat.label, marginX + 4, currentY + 4.2);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(textDark[0], textDark[1], textDark[2]);
    doc.text(`${stat.count} achado(s)`, marginX + 40, currentY + 4.2);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text(`${stat.points} pts / ocorrência`, marginX + 75, currentY + 4.2);
    doc.text(stat.desc, marginX + 115, currentY + 4.2);

    currentY += 6;
  });

  currentY += 6;

  // ==========================================
  // 4. PLANO EXECUTIVO DE MITIGAÇÃO
  // ==========================================
  checkPageBreak(50);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.text('3. PLANO EXECUTIVO DE MITIGAÇÃO & RECOMENDAÇÕES', marginX, currentY);
  currentY += 4;

  const recommendations = [
    {
      phase: 'FASE 1: IMEDIATO (0 - 24 HORAS)',
      action: 'Revogação & Rotação de Credenciais Expostas',
      details: 'Todas as chaves AWS, tokens Stripe e segredos identificados devem ser imediatamente revogados nos provedores de nuvem e substituídos por novas credenciais rotacionadas.',
      badge: 'URGENTE',
      color: [211, 47, 47]
    },
    {
      phase: 'FASE 2: CURTO PRAZO (1 - 3 DIAS)',
      action: 'Sanitização de Histórico Git & Desacoplamento de .env',
      details: 'Garantir que arquivos .env estejam no .gitignore. Caso arquivos com segredos tenham sido commitados, utilizar ferramentas como git-filter-repo ou BFG para expurgar do histórico permanente.',
      badge: 'PRIORITÁRIO',
      color: [230, 81, 0]
    },
    {
      phase: 'FASE 3: MÉDIO PRAZO (1 SEMANA)',
      action: 'Adoção de Secret Vault Centralizado',
      details: 'Migrar variáveis sensíveis de código estático para cofres gerenciados: AWS Secrets Manager, HashiCorp Vault, Doppler ou GCP Secret Manager, com injeção em tempo de execução.',
      badge: 'ESTRUTURAL',
      color: [161, 98, 7]
    },
    {
      phase: 'FASE 4: PREVENÇÃO CONTÍNUA (CI/CD)',
      action: 'Enforcement de Quality Gates no Pré-Push e Pipeline',
      details: 'Adicionar SecScan.js com bloqueio estrito (--fail-on critical) em GitHub Actions ou GitLab CI para impedir merges de código vulnerável.',
      badge: 'CONTINUOUS',
      color: [29, 78, 216]
    }
  ];

  recommendations.forEach((rec) => {
    checkPageBreak(18);
    doc.setFillColor(252, 252, 252);
    doc.rect(marginX, currentY, contentWidth, 14, 'F');
    doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
    doc.setLineWidth(0.2);
    doc.rect(marginX, currentY, contentWidth, 14, 'S');

    // Left phase bar
    doc.setFillColor(rec.color[0], rec.color[1], rec.color[2]);
    doc.rect(marginX, currentY, 2, 14, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(rec.color[0], rec.color[1], rec.color[2]);
    doc.text(rec.phase, marginX + 5, currentY + 4);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(textDark[0], textDark[1], textDark[2]);
    doc.text(rec.action, marginX + 65, currentY + 4);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(80, 80, 80);
    const splitDetails = doc.splitTextToSize(rec.details, contentWidth - 10);
    doc.text(splitDetails, marginX + 5, currentY + 8);

    currentY += 16;
  });

  currentY += 4;

  // ==========================================
  // 5. INVENTÁRIO CONSOLIDADO DE VULNERABILIDADES
  // ==========================================
  checkPageBreak(30);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(primaryDark[0], primaryDark[1], primaryDark[2]);
  doc.text('4. INVENTÁRIO DETALHADO DE ACHADOS & ANÁLISE FORENSE', marginX, currentY);
  currentY += 4;

  if (report.findings.length === 0) {
    doc.setFillColor(240, 253, 244);
    doc.rect(marginX, currentY, contentWidth, 14, 'F');
    doc.setDrawColor(187, 247, 208);
    doc.rect(marginX, currentY, contentWidth, 14, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(22, 101, 52);
    doc.text('NENHUMA VULNERABILIDADE DETECTADA', marginX + 6, currentY + 6);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.text('Todos os arquivos analisados estão em conformidade estrita com as regras SAST ativas.', marginX + 6, currentY + 10.5);
    currentY += 18;
  } else {
    // Sort findings by severity weight descending
    const sortedFindings = [...report.findings].sort((a, b) => {
      const order: Record<SeverityLevel, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
      return order[b.severity] - order[a.severity];
    });

    sortedFindings.forEach((finding: ScanFinding, index: number) => {
      checkPageBreak(28);

      const sevColor = getSeverityColors(finding.severity);

      // Card container
      doc.setFillColor(254, 254, 254);
      doc.rect(marginX, currentY, contentWidth, 24, 'F');
      doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
      doc.setLineWidth(0.2);
      doc.rect(marginX, currentY, contentWidth, 24, 'S');

      // Severity badge on top-left
      doc.setFillColor(sevColor.bg[0], sevColor.bg[1], sevColor.bg[2]);
      doc.rect(marginX + 3, currentY + 3, 22, 4.5, 'F');
      doc.setDrawColor(sevColor.border[0], sevColor.border[1], sevColor.border[2]);
      doc.rect(marginX + 3, currentY + 3, 22, 4.5, 'S');

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(sevColor.text[0], sevColor.text[1], sevColor.text[2]);
      doc.text(finding.severity, marginX + 5, currentY + 6.2);

      // Finding ID and Title
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      doc.text(`#${index + 1}  ${finding.ruleName} (${finding.ruleId})`, marginX + 28, currentY + 6.2);

      // File & Line
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text(`Arquivo: ${finding.file}:${finding.line}   •   Risk Score: ${finding.riskScore ?? 'N/A'}/100   •   Entropia: ${finding.entropy.toFixed(2)} bits   •   Criticidade: ${finding.fileCriticality ?? 'NORMAL'}`, marginX + 28, currentY + 10.5);

      // Masked Secret Snippet Box
      doc.setFillColor(245, 245, 245);
      doc.rect(marginX + 3, currentY + 12, contentWidth - 6, 5, 'F');
      doc.setFont('courier', 'bold');
      doc.setFontSize(7);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      const maskedText = `Match: ${finding.maskedSecret || finding.snippet.slice(0, 60)}`;
      doc.text(maskedText.slice(0, 85), marginX + 5, currentY + 15.5);

      // Remediation text
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(accentRed[0], accentRed[1], accentRed[2]);
      const remText = `Remediação: ${finding.remediation}`;
      const splitRem = doc.splitTextToSize(remText, contentWidth - 8);
      doc.text(splitRem, marginX + 4, currentY + 20.5);

      currentY += 26;
    });
  }

  // ==========================================
  // 6. ROTAS DE API & SUPERFÍCIE DE ATAQUE
  // ==========================================
  if (report.apiEndpoints.length > 0) {
    checkPageBreak(30);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(primaryDark[0], primaryDark[1], primaryDark[2]);
    doc.text('5. MAPEAMENTO DE SUPERFÍCIE DE ATAQUE (ENDPOINTS)', marginX, currentY);
    currentY += 4;

    doc.setFillColor(primaryDark[0], primaryDark[1], primaryDark[2]);
    doc.rect(marginX, currentY, contentWidth, 5.5, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(255, 255, 255);
    doc.text('MÉTODO', marginX + 4, currentY + 3.8);
    doc.text('CAMINHO / ENDPOINT', marginX + 28, currentY + 3.8);
    doc.text('ARQUIVO DE ORIGEM', marginX + 90, currentY + 3.8);
    doc.text('CLASSIFICAÇÃO', marginX + 145, currentY + 3.8);

    currentY += 5.5;

    report.apiEndpoints.slice(0, 15).forEach((ep, i) => {
      checkPageBreak(7);
      const isEven = i % 2 === 0;
      doc.setFillColor(isEven ? 255 : 248, isEven ? 255 : 248, isEven ? 255 : 248);
      doc.rect(marginX, currentY, contentWidth, 5.5, 'F');
      doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
      doc.setLineWidth(0.15);
      doc.line(marginX, currentY + 5.5, marginX + contentWidth, currentY + 5.5);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(textDark[0], textDark[1], textDark[2]);
      doc.text(ep.method || 'GET', marginX + 4, currentY + 3.8);

      doc.setFont('courier', 'normal');
      doc.setFontSize(6.5);
      doc.text(ep.path.slice(0, 36), marginX + 28, currentY + 3.8);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6);
      doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
      doc.text(`${ep.file}:${ep.line}`.slice(0, 32), marginX + 90, currentY + 3.8);

      if (ep.isInternalOrAdmin) {
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(211, 47, 47);
        doc.text('INTERNO / ADMIN', marginX + 145, currentY + 3.8);
      } else {
        doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
        doc.text('PÚBLICO / PADRÃO', marginX + 145, currentY + 3.8);
      }

      currentY += 5.5;
    });

    currentY += 6;
  }

  // ==========================================
  // FOOTER & PAGE NUMBERING (ALL PAGES)
  // ==========================================
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setDrawColor(borderGray[0], borderGray[1], borderGray[2]);
    doc.setLineWidth(0.2);
    doc.line(marginX, pageHeight - 12, marginX + contentWidth, pageHeight - 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(textMuted[0], textMuted[1], textMuted[2]);
    doc.text('SECSCAN.JS • AUDITORIA CONFIDENCIAL DE SEGURANÇA DA INFORMAÇÃO', marginX, pageHeight - 8);
    doc.text(`Página ${p} de ${totalPages}`, marginX + contentWidth - 20, pageHeight - 8);
  }

  return doc;
}

export function downloadSecurityReportPdf(
  report: ScanReport,
  customFilename?: string
): void {
  const doc = generateSecurityReportPdf(report);
  const fileName = customFilename || `secscan-executive-security-report-${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(fileName);
}
