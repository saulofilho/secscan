import React, { createContext, useContext, useState, useEffect, ReactNode, useMemo, useRef } from 'react';
import { safeGetItem, safeSetItem } from './storage';

export type SupportedLanguage = 'pt' | 'en' | 'es';

export interface LanguageInfo {
  code: SupportedLanguage;
  name: string;
  nativeName: string;
  flag: string;
  locale: string;
}

export const SUPPORTED_LANGUAGES: LanguageInfo[] = [
  {
    code: 'pt',
    name: 'Português',
    nativeName: 'Português (Brasil)',
    flag: '🇧🇷',
    locale: 'pt-BR'
  },
  {
    code: 'en',
    name: 'English',
    nativeName: 'English (US)',
    flag: '🇺🇸',
    locale: 'en-US'
  },
  {
    code: 'es',
    name: 'Español',
    nativeName: 'Español',
    flag: '🇪🇸',
    locale: 'es-ES'
  }
];

// Phase 1: Compound phrases sorted by descending length to match compound terms before single words
export const PHRASE_DICTIONARY: Array<[string, string, string]> = [
  // Compound Titles & Headers
  ["Plataforma avançada e completa de cibersegurança e AppSec", "Advanced and comprehensive cybersecurity & AppSec platform", "Plataforma avanzada y completa de ciberseguridad y AppSec"],
  ["Cyber Threat Intelligence (CTI) Hub em tempo real", "Real-Time Cyber Threat Intelligence (CTI) Hub", "Hub de Cyber Threat Intelligence (CTI) en tiempo real"],
  ["Pipeline Flow Architect com mapeamento visual drag-and-drop", "Pipeline Flow Architect with visual drag-and-drop mapping", "Pipeline Flow Architect con mapeo visual drag-and-drop"],
  ["Security Refactoring Assistant com sugestões de código moderno", "Security Refactoring Assistant with modern code suggestions", "Security Refactoring Assistant con sugerencias de código moderno"],
  ["Score de Risco Cumulativo do Workspace", "Cumulative Workspace Risk Score", "Puntaje de Riesgo Acumulado del Espacio de Trabajo"],
  ["Score de Risco Cumulativo", "Cumulative Risk Score", "Puntaje de Riesgo Acumulado"],
  ["Score Risco Cumulativo", "Cumulative Risk Score", "Puntaje de Riesgo Acumulado"],
  ["Score de Risco", "Risk Score", "Puntaje de Riesgo"],
  ["Score Risco:", "Risk Score:", "Puntaje Riesgo:"],
  ["Score Risco", "Risk Score", "Puntaje Riesgo"],
  ["Nível de Risco", "Risk Level", "Nivel de Riesgo"],
  ["Tempo Médio de Remediação (MTTR)", "Mean Time to Remediate (MTTR)", "Tiempo Medio de Remediación (MTTR)"],
  ["Tempo Médio de Remediação", "Mean Time to Remediate", "Tiempo Medio de Remediación"],
  ["Taxa de Falsos Positivos", "False Positive Rate", "Tasa de Falsos Positivos"],
  ["Visão executiva com Risk Score cumulativo", "Executive view with cumulative Risk Score", "Vista ejecutiva con puntaje de riesgo acumulado"],
  ["Auditoria de código linha a linha", "Line-by-line code audit", "Auditoría de código línea por línea"],
  ["Mapeamento de rotas REST, GraphQL", "Mapping of REST routes, GraphQL", "Mapeo de rutas REST, GraphQL"],
  ["Mineração de bundles JS", "JS bundle mining", "Minería de bundles JS"],
  ["Grafo D3 de fluxo de dados não confiáveis", "D3 untrusted data flow graph", "Grafo D3 de flujo de datos no confiables"],
  ["Testes de segurança interativos em tempo de execução", "Interactive runtime application security testing", "Pruebas de seguridad interactivas en tiempo de ejecución"],
  ["Auditoria de dependências open-source", "Open-source dependency audit", "Auditoría de dependencias de código abierto"],
  ["Análise estática de infraestrutura", "Static infrastructure analysis", "Análisis estático de infraestructura"],
  ["Auditoria especializada de APIs", "Specialized API audit", "Auditoría especializada de APIs"],
  ["Gestão de Débito Técnico", "Technical Debt Management", "Gestión de Deuda Técnica"],
  ["Fuzzer de injeção em APIs", "API injection fuzzer", "Fuzzer de inyección en APIs"],
  ["Gerador de Software Bill of Materials", "Software Bill of Materials (SBOM) Generator", "Generador de Software Bill of Materials (SBOM)"],
  ["Varredura por Entropia de Shannon", "Shannon Entropy Scan", "Escaneo por Entropía de Shannon"],
  ["Modelagem de Ameaças STRIDE & CVSS", "STRIDE & CVSS Threat Modeling", "Modelado de Amenazas STRIDE & CVSS"],
  ["Hub Integrado de Inteligência de Ameaças", "Integrated Threat Intelligence Hub", "Hub Integrado de Inteligencia de Amenazas"],
  ["Motor de Auto-Remediação Automatizada", "Automated Auto-Remediation Engine", "Motor de Auto-Remediación Automatizada"],
  ["Assistente Inteligente de Refatoração", "Intelligent Refactoring Assistant", "Asistente Inteligente de Refactorización"],
  ["Playbooks SOAR Visuais", "Visual SOAR Playbooks", "Playbooks SOAR Visuales"],
  ["Segurança em Aplicações LLM & IA Generativa", "LLM & Generative AI Security", "Seguridad en Aplicaciones LLM e IA Generativa"],
  ["Suíte de 10 Ferramentas Profissionais", "10 Professional Tools Suite", "Suite de 10 Herramientas Profesionales"],
  ["Governança de Políticas como Código", "Policy-as-Code Governance", "Gobernanza de Políticas como Código"],
  ["Prontidão de Conformidade Regulatória", "Regulatory Compliance Readiness", "Preparación de Cumplimiento Regulatorio"],
  ["Hub de Frameworks & Normas Globais", "Global Frameworks & Standards Hub", "Hub de Frameworks y Normas Globales"],
  ["Painel Operacional SOC 24/7", "24/7 SOC Operational Dashboard", "Panel Operacional SOC 24/7"],
  ["Integração Nativa Security Onion SOC", "Security Onion SOC Native Integration", "Integración Nativa Security Onion SOC"],
  ["Integração Falcon CrowdStrike", "CrowdStrike Falcon Integration", "Integración CrowdStrike Falcon"],
  ["Detecção e Resposta em Endpoints (EDR)", "Endpoint Detection and Response (EDR)", "Detección y Respuesta en Endpoints (EDR)"],
  ["Varredura e Mapeamento de Rede Nmap", "Nmap Network Scan and Mapping", "Escaneo y Mapeo de Red Nmap"],
  ["Scanner de Servidores Web Nikto", "Nikto Web Server Scanner", "Escáner de Servidores Web Nikto"],
  ["Next-Gen Firewall (NGFW)", "Next-Gen Firewall (NGFW)", "Next-Gen Firewall (NGFW)"],
  ["Sistemas de Detecção e Prevenção de Intrusão (IDS/IPS)", "Intrusion Detection and Prevention Systems (IDS/IPS)", "Sistemas de Detección y Prevención de Intrusiones (IDS/IPS)"],
  ["Segurança DNS & DNSSEC", "DNS Security & DNSSEC", "Seguridad DNS y DNSSEC"],
  ["Web Application Firewall (WAF)", "Web Application Firewall (WAF)", "Web Application Firewall (WAF)"],
  ["Rede Definida por Software (SD-WAN)", "Software-Defined WAN (SD-WAN)", "Red Definida por Software (SD-WAN)"],
  ["Auditoria de Cabeçalhos HTTP & CSP", "HTTP Headers & CSP Audit", "Auditoría de Cabeceras HTTP y CSP"],
  ["Segurança de Containers Docker & Kubernetes", "Docker & Kubernetes Container Security", "Seguridad de Contenedores Docker y Kubernetes"],
  ["Auditoria de Permissões e Políticas Cloud IAM", "Cloud IAM Permissions & Policies Audit", "Auditoría de Permisos y Políticas Cloud IAM"],
  ["Forense de Tokens JWT e Chaves de Sessão", "JWT Token & Session Key Forensics", "Forense de Tokens JWT y Claves de Sesión"],
  ["Validador e Firewall contra SSRF", "SSRF Validator & Firewall", "Validador y Firewall contra SSRF"],
  ["Editor e Avaliador de Regras Regex", "Regex Rules Editor & Evaluator", "Editor y Evaluador de Regras Regex"],
  ["Terminal e Interface de Linha de Comando (CLI)", "Command Line Interface (CLI) & Terminal", "Terminal e Interfaz de Línea de Comandos (CLI)"],
  ["Integração e Automação CI/CD", "CI/CD Integration & Automation", "Integración y Automatización CI/CD"],

  // Metrics and Dashboard Terms
  ["Arquivos Processados no Workspace", "Workspace Processed Files", "Archivos Procesados en el Espacio de Trabajo"],
  ["Arquivos Processados", "Processed Files", "Archivos Procesados"],
  ["Linhas Totais de Código Auditadas", "Total Audited Lines of Code", "Líneas Totales de Código Auditadas"],
  ["Linhas Auditadas", "Audited Lines", "Líneas Auditadas"],
  ["Rotas & Endpoints Mapeados", "Mapped Routes & Endpoints", "Rutas y Endpoints Mapeados"],
  ["Rotas e Endpoints", "Routes and Endpoints", "Rutas y Endpoints"],
  ["Tempo Total de Execução", "Total Execution Time", "Tiempo Total de Ejecución"],
  ["Tempo de Execução", "Execution Time", "Tiempo de Ejecución"],
  ["Velocímetro de Execução", "Execution Speedometer", "Velocímetro de Ejecución"],
  ["Status Geral do Sistema", "General System Status", "Estado General del Sistema"],
  ["Taxa de Resolução", "Resolution Rate", "Tasa de Resolución"],
  ["Distribuição por Criticidade", "Criticality Distribution", "Distribución por Criticidad"],
  ["Distribuição por Severidade", "Severity Distribution", "Distribución por Severidad"],
  ["Severidade das Vulnerabilidades", "Vulnerability Severity", "Severidad de las Vulnerabilidades"],
  ["Últimos 10 Scans Realizados", "Last 10 Scans Performed", "Últimos 10 Escaneos Realizados"],
  ["Histórico de Varreduras", "Scan History", "Historial de Escaneos"],
  ["Resumo da Postura de Segurança", "Security Posture Summary", "Resumen de Postura de Seguridad"],
  ["Débito Técnico de Segurança", "Security Technical Debt", "Deuda Técnica de Seguridad"],
  ["Cumprimento de SLAs", "SLA Compliance", "Cumplimiento de SLAs"],
  ["Roadmap Estratégico de Remediação", "Strategic Remediation Roadmap", "Hoja de Ruta Estratégica de Remediación"],
  ["Prioridade P0 - Imediata", "Priority P0 - Immediate", "Prioridad P0 - Inmediata"],
  ["Prioridade P1 - Alta", "Priority P1 - High", "Prioridad P1 - Alta"],
  ["Prioridade P2 - Média", "Priority P2 - Medium", "Prioridad P2 - Media"],
  ["Prontidão de Conformidade", "Compliance Readiness", "Preparación de Cumplimiento"],
  ["Práticas de Segurança", "Security Practices", "Buenas Prácticas de Seguridad"],
  ["Vulnerabilidades Mais Críticas", "Most Critical Vulnerabilities", "Vulnerabilidades Más Críticas"],
  ["Top Arquivos Vulneráveis", "Top Vulnerable Files", "Archivos Más Vulnerables"],

  // Dashboard Overview Cards & UI
  ["Visão Geral & Métricas", "Overview & Metrics", "Visión General y Métricas"],
  ["Visão Geral e Métricas", "Overview and Metrics", "Visión General y Métricas"],
  ["Dashboard & Métricas Executivas", "Dashboard & Executive Metrics", "Panel y Métricas Ejecutivas"],
  ["Auditar Achados no Scanner", "Audit Findings in Scanner", "Auditar Hallazgos en el Escáner"],
  ["Auditar Achados", "Audit Findings", "Auditar Hallazgos"],
  ["Achados no Scanner", "Scanner Findings", "Hallazgos en el Escáner"],
  ["Roteiro de Redução (Top 3)", "Reduction Roadmap (Top 3)", "Hoja de Reducción (Top 3)"],
  ["Roteiro de Redução", "Reduction Roadmap", "Hoja de Reducción"],
  ["Ajustar Limite", "Adjust Threshold", "Ajustar Límite"],
  ["Baixar Relatório PDF", "Download PDF Report", "Descargar Reporte PDF"],
  ["Baixar Relatório", "Download Report", "Descargar Reporte"],
  ["Visão Executiva", "Executive View", "Vista Ejecutiva"],
  ["Tendências & Histórico", "Trends & History", "Tendencias e Historial"],
  ["Tendências e Histórico", "Trends and History", "Tendencias e Historial"],
  ["Heatmaps & Matriz", "Heatmaps & Matrix", "Mapas de Calor y Matriz"],
  ["Remediação & SLAs", "Remediation & SLAs", "Remediación y SLAs"],
  ["Remediação e SLAs", "Remediation and SLAs", "Remediación y SLAs"],
  ["Risk Calculator", "Risk Calculator", "Calculadora de Riesgo"],
  ["Exibir Tudo", "Show All", "Mostrar Todo"],
  ["Top Concentração:", "Top Concentration:", "Mayor Concentración:"],
  ["Top Concentração", "Top Concentration", "Mayor Concentración"],
  ["Voltar para Visão Geral Executiva", "Back to Executive Overview", "Volver a la Visión General Ejecutiva"],
  ["Voltar para Visão Geral", "Back to Overview", "Volver a la Visión General"],
  ["Análise Dinâmica", "Dynamic Analysis", "Análisis Dinámico"],
  ["Análise Estática", "Static Analysis", "Análisis Estático"],
  ["Alerta Automatizado: Limite Global de Risco Ultrapassado", "Automated Alert: Global Risk Threshold Exceeded", "Alerta Automatizada: Límite Global de Riesgo Superado"],
  ["Alerta Automatizado", "Automated Alert", "Alerta Automatizada"],
  ["Limite Global de Risco Ultrapassado", "Global Risk Threshold Exceeded", "Límite Global de Riesgo Superado"],
  ["Limite de Achados Críticos Ultrapassado", "Critical Findings Threshold Exceeded", "Límite de Hallazgos Críticos Superado"],
  ["Alta Severidade (HIGH)", "High Severity (HIGH)", "Alta Severidad (HIGH)"],
  ["Média Severidade (MEDIUM)", "Medium Severity (MEDIUM)", "Media Severidad (MEDIUM)"],
  ["Baixa Severidade (LOW)", "Low Severity (LOW)", "Baja Severidad (LOW)"],
  ["Alta Gravidade", "High Severity", "Alta Gravedad"],
  ["Média Gravidade", "Medium Severity", "Media Gravedad"],
  ["Baixa Gravidade", "Low Severity", "Baja Gravedad"],
  ["Crítica Gravidade", "Critical Severity", "Gravedad Crítica"],
  ["Excedido por", "Exceeded by", "Superado por"],
  ["ocorrência(s)", "occurrence(s)", "ocurrencia(s)"],
  ["Teto Máximo Tolerado", "Maximum Tolerated Ceiling", "Techo Máximo Tolerado"],
  ["Configurar Risk Threshold", "Configure Risk Threshold", "Configurar Umbral de Riesgo"],

  // Action Buttons & Common Interactive Terms
  ["Executar Análise SAST", "Run SAST Analysis", "Ejecutar Análisis SAST"],
  ["Executar Varredura", "Run Scan", "Ejecutar Escaneo"],
  ["Executar Novamente", "Run Again", "Ejecutar Nuevamente"],
  ["Analisando arquivos...", "Analyzing files...", "Analizando archivos..."],
  ["Analisando...", "Analyzing...", "Analizando..."],
  ["Quick Rescan", "Quick Rescan", "Reescaneo Rápido"],
  ["Restaurar Demo", "Restore Demo", "Restaurar Demo"],
  ["Limpar Workspace", "Clear Workspace", "Limpiar Espacio de Trabajo"],
  ["Include Summary Metadata", "Include Summary Metadata", "Incluir Metadatos de Resumen"],
  ["Incluir Metadados de Sumário", "Include Summary Metadata", "Incluir Metadatos de Resumen"],
  ["WITH SUMMARY", "WITH SUMMARY", "CON RESUMEN"],
  ["FINDINGS ONLY", "FINDINGS ONLY", "SOLO HALLAZGOS"],
  ["FULL AUDIT", "FULL AUDIT", "AUDITORÍA COMPLETA"],
  ["ONLY FINDINGS", "ONLY FINDINGS", "SOLO HALLAZGOS"],
  ["Exportar Relatório de Segurança", "Export Security Report", "Exportar Reporte de Seguridad"],
  ["Exportar Relatório", "Export Report", "Exportar Reporte"],
  ["Escolha o formato adequado para auditoria, esteira de CI/CD ou integração nativa com GitHub Advanced Security", "Choose the appropriate format for audit, CI/CD pipeline or native integration with GitHub Advanced Security", "Elija el formato adecuado para auditoría, pipeline de CI/CD o integración nativa con GitHub Advanced Security"],
  ["Escolha o formato adequado para sua esteira de CI/CD ou auditoria de conformidade", "Choose the appropriate format for your CI/CD pipeline or compliance audit", "Elija el formato adecuado para su pipeline de CI/CD o auditoría de cumplimiento"],
  ["Compatível com GitHub Advanced Security / Code Scanning, GitLab SAST, SonarQube, DefectDojo e Azure DevOps.", "Compatible with GitHub Advanced Security / Code Scanning, GitLab SAST, SonarQube, DefectDojo and Azure DevOps.", "Compatible con GitHub Advanced Security / Code Scanning, GitLab SAST, SonarQube, DefectDojo y Azure DevOps."],
  ["Baixar workflow do GitHub Actions", "Download GitHub Actions workflow", "Descargar workflow de GitHub Actions"],
  ["Baixar arquivo .sarif dos achados", "Download .sarif findings file", "Descargar archivo .sarif de los hallazgos"],
  ["Baixar Workflow (.yml)", "Download Workflow (.yml)", "Descargar Workflow (.yml)"],
  ["Baixar .sarif", "Download .sarif", "Descargar .sarif"],
  ["BAIXAR (SARIF 2.1.0)", "DOWNLOAD (SARIF 2.1.0)", "DESCARGAR (SARIF 2.1.0)"],
  ["BAIXAR (WORKFLOW .YML)", "DOWNLOAD (WORKFLOW .YML)", "DESCARGAR (WORKFLOW .YML)"],
  ["GERANDO PDF...", "GENERATING PDF...", "GENERANDO PDF..."],
  ["Importar Workspace", "Import Workspace", "Importar Espacio de Trabajo"],
  ["Adicionar Arquivo", "Add File", "Agregar Archivo"],
  ["Novo Arquivo", "New File", "Nuevo Archivo"],
  ["Remover Arquivo", "Remove File", "Eliminar Archivo"],
  ["Salvar Alterações", "Save Changes", "Guardar Cambios"],
  ["Padrões Ignorados", "Ignored Patterns", "Patrones Ignorados"],
  ["Adicionar Novo Padrão", "Add New Pattern", "Agregar Nuevo Patrón"],
  ["Glossário de Cibersegurança & AppSec", "Cybersecurity & AppSec Glossary", "Glosario de Ciberseguridad y AppSec"],
  ["Buscar vulnerabilidade ou termo...", "Search vulnerability or term...", "Buscar vulnerabilidad o término..."],
  ["Auditoria de Higiene de Repositório Git", "Git Repository Hygiene Audit", "Auditoría de Higiene de Repositorio Git"],
  ["Nenhuma vulnerabilidade ou segredo exposto detectado nesta execução.", "No vulnerabilities or exposed secrets detected in this run.", "No se detectaron vulnerabilidades o secretos expuestos en esta ejecución."],
  ["Nenhuma vulnerabilidade detectada", "No vulnerabilities detected", "No se detectaron vulnerabilidades"],
  ["Nenhum achado encontrado", "No findings found", "No se encontraron hallazgos"],
  ["Nenhum arquivo encontrado", "No files found", "No se encontraron archivos"],
  ["Selecione um arquivo da lista para visualizar o código.", "Select a file from the list to view the code.", "Seleccione un archivo de la lista para ver el código."],
  ["Selecione um item para ver detalhes", "Select an item to view details", "Seleccione un elemento para ver detalles"],
  ["Selecione um pacote na lista para visualizar o dossiê detalhado", "Select a package from the list to view the detailed dossier", "Seleccione un paquete de la lista para ver el dossier detallado"],
  ["Selecione uma vulnerabilidade de IaC na lista", "Select an IaC vulnerability from the list", "Seleccione una vulnerabilidad de IaC de la lista"],
  ["Clique nos cards para expandir/recolher", "Click cards to expand/collapse", "Haga clic en las tarjetas para expandir/contraer"],
  ["Clique para visualizar detalhes de cálculo.", "Click to view calculation details.", "Haga clic para ver los detalles de cálculo."],
  ["Clique em qualquer ponto do gráfico", "Click anywhere on the chart", "Haga clic en cualquier punto del gráfico"],
  ["Clique em qualquer célula de severidade", "Click on any severity cell", "Haga clic en cualquier celda de severidad"],

  // Navigation Tabs
  ["Dashboard & Métricas", "Dashboard & Metrics", "Panel y Métricas"],
  ["Inspetor de Código", "Code Inspector", "Inspector de Código"],
  ["Rotas & Endpoints", "Routes & Endpoints", "Rutas y Endpoints"],
  ["Fluxo D3 Taint", "D3 Taint Flow", "Flujo D3 Taint"],
  ["Mapeamento Visual", "Visual Mapping", "Mapeo Visual"],
  ["IAST Suite", "IAST Suite", "Suite IAST"],
  ["SCA Dependências", "SCA Dependencies", "SCA Dependencias"],
  ["IaC Segurança", "IaC Security", "Seguridad IaC"],
  ["ASOC & SLA", "ASOC & SLA", "ASOC y SLA"],
  ["DAST Fuzzer", "DAST Fuzzer", "Fuzzer DAST"],
  ["SBOM Generator", "SBOM Generator", "Generador SBOM"],
  ["Entropia Shannon", "Shannon Entropy", "Entropía Shannon"],
  ["STRIDE Threat", "STRIDE Threat", "Amenaza STRIDE"],
  ["CTI Threat Intel", "CTI Threat Intel", "CTI Threat Intel"],
  ["Auto-Remediação", "Auto-Remediation", "Auto-Remediación"],
  ["Refatoração IA", "AI Refactoring", "Refactorización IA"],
  ["Visual SOAR", "Visual SOAR", "SOAR Visual"],
  ["LLM Security", "LLM Security", "Seguridad LLM"],
  ["Pro Sec Tools", "Pro Sec Tools", "Herramientas Pro Sec"],
  ["Policy as Code", "Policy as Code", "Política como Código"],
  ["Compliance Readiness", "Compliance Readiness", "Preparación de Cumplimiento"],
  ["Global Frameworks", "Global Frameworks", "Frameworks Globales"],
  ["24/7 SOC Radar", "24/7 SOC Radar", "Radar SOC 24/7"],
  ["Security Onion", "Security Onion", "Security Onion"],
  ["CrowdStrike", "CrowdStrike", "CrowdStrike"],
  ["EDR Suite", "EDR Suite", "Suite EDR"],
  ["Nmap Network", "Nmap Network", "Red Nmap"],
  ["Nikto Web", "Nikto Web", "Web Nikto"],
  ["NGFW Firewall", "NGFW Firewall", "Firewall NGFW"],
  ["IDS/IPS Suite", "IDS/IPS Suite", "Suite IDS/IPS"],
  ["DNS Security", "DNS Security", "Seguridad DNS"],
  ["WAF Protection", "WAF Protection", "Protección WAF"],
  ["SD-WAN Suite", "SD-WAN Suite", "Suite SD-WAN"],
  ["HTTP/CSP Headers", "HTTP/CSP Headers", "Cabeceras HTTP/CSP"],
  ["Containers Docker", "Docker Containers", "Contenedores Docker"],
  ["Cloud IAM Audit", "Cloud IAM Audit", "Auditoría Cloud IAM"],
  ["JWT Forensics", "JWT Forensics", "Forense JWT"],
  ["SSRF Validator", "SSRF Validator", "Validador SSRF"],
  ["Regras Regex", "Regex Rules", "Reglas Regex"],
  ["Terminal CLI", "CLI Terminal", "Terminal CLI"],
  ["Pipeline Architect", "Pipeline Architect", "Arquitecto de Pipeline"],
  ["CI/CD & Cloud", "CI/CD & Cloud", "CI/CD y Cloud"],

  // Contextual phrases with connectives
  ["no workspace", "in workspace", "en el espacio de trabajo"],
  ["no scanner", "in scanner", "en el escáner"],
  ["no repositório", "in repository", "en el repositorio"],
  ["no arquivo", "in file", "en el archivo"],
  ["no código", "in code", "en el código"],
  ["na linha", "at line", "en la línea"],
  ["na esteira", "in pipeline", "en el pipeline"],
  ["do workspace", "of the workspace", "del espacio de trabajo"],
  ["do sistema", "of the system", "del sistema"],
  ["do arquivo", "of the file", "del archivo"],
  ["do repositório", "of the repository", "del repositorio"],
  ["da aplicação", "of the application", "de la aplicación"],
  ["da esteira", "of the pipeline", "de la esteira"],
  ["dos achados", "of findings", "de los hallazgos"],
  ["das vulnerabilidades", "of vulnerabilities", "de las vulnerabilidades"],
  ["dos arquivos", "of files", "de los archivos"],
  ["os arquivos", "the files", "los archivos"],
  ["as regras", "the rules", "las reglas"],
  ["os achados", "the findings", "los hallazgos"],
  ["as vulnerabilidades", "the vulnerabilities", "las vulnerabilidades"],
  ["as dependências", "the dependencies", "las dependencias"],
  ["os pacotes", "the packages", "los paquetes"],
  ["os endpoints", "the endpoints", "los endpoints"],
  ["as rotas", "the routes", "las rutas"],
  ["os módulos", "the modules", "los módulos"],
  ["sem vulnerabilidades", "without vulnerabilities", "sin vulnerabilidades"],
  ["sem falhas", "without flaws", "sin fallas"],
  ["sem segredos", "without secrets", "sin secretos"],
  ["com sucesso", "successfully", "con éxito"],
  ["com falhas", "with flaws", "con fallas"],
  ["com avisos", "with warnings", "con advertencias"],
  ["por severidade", "by severity", "por severidad"],
  ["por criticidade", "by criticality", "por criticidad"],
  ["por categoria", "by category", "por categoría"],
  ["por arquivo", "by file", "por archivo"],
  ["para análise", "for analysis", "para análisis"],
  ["para correção", "for fix", "para corrección"],
  ["para remediação", "for remediation", "para remediación"],
  ["nenhum achado encontrado", "no findings found", "ningún hallazgo encontrado"],
  ["nenhum achado", "no findings", "ningún hallazgo"],
  ["nenhuma vulnerabilidade encontrada", "no vulnerabilities found", "ninguna vulnerabilidad encontrada"],
  ["nenhuma vulnerabilidade", "no vulnerabilities", "ninguna vulnerabilidad"],
  ["nenhum arquivo encontrado", "no files found", "ningún archivo encontrado"],
  ["nenhum arquivo", "no files", "ningún archivo"],
  ["nenhum segredo", "no secrets", "ningún secreto"],
  ["salvar como", "save as", "guardar como"],
  ["exportar como", "export as", "exportar como"],
  ["como usar", "how to use", "cómo usar"]
];

// Phase 2: Word-level bilingual dictionary for complete coverage of all words
export const WORD_DICTIONARY: Record<string, { en: string; es: string }> = {
  // Common UI verbs & actions
  "excedendo": { en: "exceeding", es: "superando" },
  "ultrapassando": { en: "exceeding", es: "superando" },
  "contendo": { en: "containing", es: "conteniendo" },
  "incluindo": { en: "including", es: "incluyendo" },
  "excluindo": { en: "excluding", es: "excluyendo" },
  "garantindo": { en: "ensuring", es: "garantizando" },
  "verificando": { en: "checking", es: "verificando" },
  "gerando": { en: "generating", es: "generando" },
  "ocorrendo": { en: "occurring", es: "ocurriendo" },
  "utilizando": { en: "using", es: "utilizando" },
  "usando": { en: "using", es: "usando" },
  "auditar": { en: "audit", es: "auditar" },
  "auditando": { en: "auditing", es: "auditando" },
  "auditada": { en: "audited", es: "auditada" },
  "auditadas": { en: "audited", es: "auditadas" },
  "auditado": { en: "audited", es: "auditado" },
  "auditados": { en: "audited", es: "auditados" },
  "executar": { en: "run", es: "ejecutar" },
  "executando": { en: "running", es: "ejecutando" },
  "execução": { en: "execution", es: "ejecución" },
  "execuções": { en: "executions", es: "ejecuciones" },
  "analisar": { en: "analyze", es: "analizar" },
  "analisando": { en: "analyzing", es: "analizando" },
  "analisado": { en: "analyzed", es: "analizado" },
  "analisados": { en: "analyzed", es: "analizados" },
  "análise": { en: "analysis", es: "análisis" },
  "análises": { en: "analyses", es: "análisis" },
  "varrer": { en: "scan", es: "escanear" },
  "varrendo": { en: "scanning", es: "escaneando" },
  "varredura": { en: "scan", es: "escaneo" },
  "varreduras": { en: "scans", es: "escaneos" },
  "exportar": { en: "export", es: "exportar" },
  "exportando": { en: "exporting", es: "exportando" },
  "exportação": { en: "export", es: "exportación" },
  "importar": { en: "import", es: "importar" },
  "importando": { en: "importing", es: "importando" },
  "importação": { en: "import", es: "importación" },
  "baixar": { en: "download", es: "descargar" },
  "download": { en: "download", es: "descargar" },
  "limpar": { en: "clear", es: "limpiar" },
  "limpeza": { en: "cleanup", es: "limpieza" },
  "restaurar": { en: "restore", es: "restaurar" },
  "adicionar": { en: "add", es: "agregar" },
  "remover": { en: "remove", es: "eliminar" },
  "excluir": { en: "delete", es: "eliminar" },
  "editar": { en: "edit", es: "editar" },
  "salvar": { en: "save", es: "guardar" },
  "cancelar": { en: "cancel", es: "cancelar" },
  "confirmar": { en: "confirm", es: "confirmar" },
  "fechar": { en: "close", es: "cerrar" },
  "abrir": { en: "open", es: "abrir" },
  "filtrar": { en: "filter", es: "filtrar" },
  "filtro": { en: "filter", es: "filtro" },
  "filtros": { en: "filters", es: "filtros" },
  "buscar": { en: "search", es: "buscar" },
  "busca": { en: "search", es: "búsqueda" },
  "pesquisar": { en: "search", es: "buscar" },
  "pesquisa": { en: "search", es: "búsqueda" },
  "visualizar": { en: "view", es: "ver" },
  "exibir": { en: "show", es: "mostrar" },
  "ocultar": { en: "hide", es: "ocultar" },
  "copiar": { en: "copy", es: "copiar" },
  "copiado": { en: "copied", es: "copiado" },
  "colar": { en: "paste", es: "pegar" },
  "configurar": { en: "configure", es: "configurar" },
  "ajustar": { en: "adjust", es: "ajustar" },
  "ajuste": { en: "adjustment", es: "ajuste" },
  "atualizar": { en: "update", es: "actualizar" },
  "gerar": { en: "generate", es: "generar" },
  "gerador": { en: "generator", es: "generador" },
  "voltar": { en: "back", es: "volver" },
  "avançar": { en: "forward", es: "avanzar" },
  "continuar": { en: "continue", es: "continuar" },
  "selecionar": { en: "select", es: "seleccionar" },
  "selecione": { en: "select", es: "seleccione" },
  "selecionado": { en: "selected", es: "seleccionado" },
  "selecionada": { en: "selected", es: "seleccionada" },
  "selecionados": { en: "selected", es: "seleccionados" },
  "clique": { en: "click", es: "haga clic" },
  "clicar": { en: "click", es: "hacer clic" },
  "expandir": { en: "expand", es: "expandir" },
  "recolher": { en: "collapse", es: "contraer" },
  "inspecionar": { en: "inspect", es: "inspeccionar" },
  "inspetor": { en: "inspector", es: "inspector" },
  "remediar": { en: "remediate", es: "remediar" },
  "mitigar": { en: "mitigate", es: "mitigar" },
  "proteger": { en: "protect", es: "proteger" },
  "prevenir": { en: "prevent", es: "prevenir" },
  "detectar": { en: "detect", es: "detectar" },
  "bloquear": { en: "block", es: "bloquear" },
  "permitir": { en: "allow", es: "permitir" },

  // Security terms
  "vulnerabilidade": { en: "vulnerability", es: "vulnerabilidad" },
  "vulnerabilidades": { en: "vulnerabilities", es: "vulnerabilidades" },
  "ameaça": { en: "threat", es: "amenaza" },
  "ameaças": { en: "threats", es: "amenazas" },
  "achado": { en: "finding", es: "hallazgo" },
  "achados": { en: "findings", es: "hallazgos" },
  "segredo": { en: "secret", es: "secreto" },
  "segredos": { en: "secrets", es: "secretos" },
  "segurança": { en: "security", es: "seguridad" },
  "cibersegurança": { en: "cybersecurity", es: "ciberseguridad" },
  "conformidade": { en: "compliance", es: "cumplimiento" },
  "remediação": { en: "remediation", es: "remediación" },
  "mitigação": { en: "mitigation", es: "mitigación" },
  "auditoria": { en: "audit", es: "auditoría" },
  "auditorias": { en: "audits", es: "auditorías" },
  "inspeção": { en: "inspection", es: "inspección" },
  "arquivo": { en: "file", es: "archivo" },
  "arquivos": { en: "files", es: "archivos" },
  "código": { en: "code", es: "código" },
  "linha": { en: "line", es: "línea" },
  "linhas": { en: "lines", es: "líneas" },
  "regra": { en: "rule", es: "regla" },
  "regras": { en: "rules", es: "reglas" },
  "política": { en: "policy", es: "política" },
  "políticas": { en: "policies", es: "políticas" },
  "pacote": { en: "package", es: "paquete" },
  "pacotes": { en: "packages", es: "paquetes" },
  "dependência": { en: "dependency", es: "dependencia" },
  "dependências": { en: "dependencies", es: "dependencias" },
  "repositório": { en: "repository", es: "repositorio" },
  "repositórios": { en: "repositories", es: "repositorios" },
  "alerta": { en: "alert", es: "alerta" },
  "alertas": { en: "alerts", es: "alertas" },
  "aviso": { en: "warning", es: "advertencia" },
  "avisos": { en: "warnings", es: "advertencias" },
  "notificação": { en: "notification", es: "notificación" },
  "notificações": { en: "notifications", es: "notificaciones" },
  "relatório": { en: "report", es: "reporte" },
  "relatórios": { en: "reports", es: "reportes" },
  "painel": { en: "panel", es: "panel" },
  "painéis": { en: "panels", es: "paneles" },
  "dossiê": { en: "dossier", es: "dossier" },
  "exclusão": { en: "exclusion", es: "exclusión" },
  "exclusões": { en: "exclusions", es: "exclusiones" },
  "glossário": { en: "glossary", es: "glosario" },
  "atalho": { en: "shortcut", es: "acceso directo" },
  "atalhos": { en: "shortcuts", es: "atajos" },
  "guia": { en: "guide", es: "guía" },
  "manual": { en: "manual", es: "manual" },
  "ajuda": { en: "help", es: "ayuda" },
  "padrão": { en: "pattern", es: "patrón" },
  "padrões": { en: "patterns", es: "patrones" },
  "ignorados": { en: "ignored", es: "ignorados" },
  "ignorado": { en: "ignored", es: "ignorado" },
  "higiene": { en: "hygiene", es: "higiene" },

  // Severities & Status
  "severidade": { en: "severity", es: "severidad" },
  "severidades": { en: "severities", es: "severidades" },
  "criticidade": { en: "criticality", es: "criticidad" },
  "gravidade": { en: "severity", es: "gravedad" },
  "crítico": { en: "critical", es: "crítico" },
  "crítica": { en: "critical", es: "crítica" },
  "críticos": { en: "critical", es: "críticos" },
  "críticas": { en: "critical", es: "críticas" },
  "alto": { en: "high", es: "alto" },
  "alta": { en: "high", es: "alta" },
  "altos": { en: "high", es: "altos" },
  "altas": { en: "high", es: "altas" },
  "médio": { en: "medium", es: "medio" },
  "média": { en: "medium", es: "media" },
  "médios": { en: "medium", es: "medios" },
  "médias": { en: "medium", es: "medias" },
  "baixo": { en: "low", es: "bajo" },
  "baixa": { en: "low", es: "baja" },
  "baixos": { en: "low", es: "bajos" },
  "baixas": { en: "low", es: "bajas" },
  "informativo": { en: "informational", es: "informativo" },
  "informativa": { en: "informational", es: "informativa" },
  "informativos": { en: "informational", es: "informativos" },
  "ativo": { en: "active", es: "activo" },
  "ativa": { en: "active", es: "activa" },
  "ativos": { en: "active", es: "activos" },
  "ativas": { en: "active", es: "activas" },
  "inativo": { en: "inactive", es: "inactivo" },
  "inativa": { en: "inactive", es: "inactiva" },
  "inativos": { en: "inactive", es: "inactivos" },
  "inativas": { en: "inactive", es: "inactivas" },
  "habilitado": { en: "enabled", es: "habilitado" },
  "habilitada": { en: "enabled", es: "habilitada" },
  "desabilitado": { en: "disabled", es: "deshabilitado" },
  "desabilitada": { en: "disabled", es: "deshabilitada" },
  "sucesso": { en: "success", es: "éxito" },
  "falha": { en: "failed", es: "fallo" },
  "falhas": { en: "flaws", es: "fallos" },
  "erro": { en: "error", es: "error" },
  "erros": { en: "errors", es: "errores" },
  "pendente": { en: "pending", es: "pendiente" },
  "concluído": { en: "completed", es: "completado" },
  "concluída": { en: "completed", es: "completada" },
  "detectado": { en: "detected", es: "detectado" },
  "detectada": { en: "detected", es: "detectada" },
  "detectados": { en: "detected", es: "detectados" },
  "detectadas": { en: "detected", es: "detectadas" },
  "excedido": { en: "exceeded", es: "superado" },
  "excedida": { en: "exceeded", es: "superada" },
  "excedidos": { en: "exceeded", es: "superados" },
  "ultrapassado": { en: "exceeded", es: "superado" },
  "ultrapassada": { en: "exceeded", es: "superada" },
  "ultrapassados": { en: "exceeded", es: "superados" },
  "tolerado": { en: "tolerated", es: "tolerado" },
  "tolerada": { en: "tolerated", es: "tolerada" },
  "processado": { en: "processed", es: "procesado" },
  "processados": { en: "processed", es: "procesados" },
  "processada": { en: "processed", es: "procesada" },
  "processadas": { en: "processed", es: "procesadas" },
  "salvo": { en: "saved", es: "guardado" },
  "salva": { en: "saved", es: "guardada" },
  "salvos": { en: "saved", es: "guardados" },
  "salvas": { en: "saved", es: "guardadas" },

  // Metrics & Analytics
  "métricas": { en: "metrics", es: "métricas" },
  "métrica": { en: "metric", es: "métrica" },
  "risco": { en: "risk", es: "riesgo" },
  "riscos": { en: "risks", es: "riesgos" },
  "pontuação": { en: "score", es: "puntaje" },
  "índice": { en: "index", es: "índice" },
  "taxa": { en: "rate", es: "tasa" },
  "taxas": { en: "rates", es: "tasas" },
  "tempo": { en: "time", es: "tiempo" },
  "duração": { en: "duration", es: "duración" },
  "total": { en: "total", es: "total" },
  "totais": { en: "total", es: "totales" },
  "mínimo": { en: "minimum", es: "mínimo" },
  "máximo": { en: "maximum", es: "máximo" },
  "limite": { en: "threshold", es: "límite" },
  "limites": { en: "thresholds", es: "límites" },
  "teto": { en: "ceiling", es: "techo" },
  "resolução": { en: "resolution", es: "resolución" },
  "redução": { en: "reduction", es: "reducción" },
  "tendência": { en: "trend", es: "tendencia" },
  "tendências": { en: "trends", es: "tendencias" },
  "histórico": { en: "history", es: "historial" },
  "resumo": { en: "summary", es: "resumen" },
  "visão": { en: "view", es: "vista" },
  "geral": { en: "overview", es: "general" },
  "executiva": { en: "executive", es: "ejecutiva" },
  "executivo": { en: "executive", es: "ejecutivo" },
  "executivas": { en: "executive", es: "ejecutivas" },
  "executivos": { en: "executive", es: "ejecutivos" },
  "estática": { en: "static", es: "estática" },
  "estático": { en: "static", es: "estático" },
  "dinâmica": { en: "dynamic", es: "dinámica" },
  "dinâmico": { en: "dynamic", es: "dinámico" },
  "automatizado": { en: "automated", es: "automatizado" },
  "automatizada": { en: "automated", es: "automatizada" },
  "automatizados": { en: "automated", es: "automatizados" },
  "automatizadas": { en: "automated", es: "automatizadas" },
  "concentração": { en: "concentration", es: "concentración" },
  "densidade": { en: "density", es: "densidad" },
  "distribuição": { en: "distribution", es: "distribución" },
  "cumulativo": { en: "cumulative", es: "acumulado" },
  "cumulativa": { en: "cumulative", es: "acumulada" },
  "percentual": { en: "percentage", es: "porcentaje" },
  "porcentagem": { en: "percentage", es: "porcentaje" },

  // Common UI words
  "detalhes": { en: "details", es: "detalles" },
  "detalhe": { en: "detail", es: "detalle" },
  "descrição": { en: "description", es: "descripción" },
  "título": { en: "title", es: "título" },
  "nome": { en: "name", es: "nombre" },
  "tipo": { en: "type", es: "tipo" },
  "tipos": { en: "types", es: "tipos" },
  "categoria": { en: "category", es: "categoría" },
  "categorias": { en: "categories", es: "categorías" },
  "ação": { en: "action", es: "acción" },
  "ações": { en: "actions", es: "acciones" },
  "opção": { en: "option", es: "opción" },
  "opções": { en: "options", es: "opciones" },
  "configuração": { en: "configuration", es: "configuración" },
  "configurações": { en: "configurations", es: "configuraciones" },
  "preferências": { en: "preferences", es: "preferencias" },
  "idioma": { en: "language", es: "idioma" },
  "idiomas": { en: "languages", es: "idiomas" },
  "usuário": { en: "user", es: "usuario" },
  "usuários": { en: "users", es: "usuarios" },
  "resultado": { en: "result", es: "resultado" },
  "resultados": { en: "results", es: "resultados" },
  "mensagem": { en: "message", es: "mensaje" },
  "mensagens": { en: "messages", es: "mensajes" },
  "ocorrência": { en: "occurrence", es: "ocurrencia" },
  "ocorrências": { en: "occurrences", es: "ocurrencias" },
  "exemplo": { en: "example", es: "ejemplo" },
  "exemplos": { en: "examples", es: "ejemplos" },
  "origem": { en: "source", es: "origen" },
  "destino": { en: "destination", es: "destino" },
  "fluxo": { en: "flow", es: "flujo" },
  "fluxos": { en: "flows", es: "flujos" },
  "rota": { en: "route", es: "ruta" },
  "rotas": { en: "routes", es: "rutas" },
  "rede": { en: "network", es: "red" },
  "redes": { en: "networks", es: "redes" },
  "porta": { en: "port", es: "puerto" },
  "portas": { en: "ports", es: "puertos" },
  "serviço": { en: "service", es: "servicio" },
  "serviços": { en: "services", es: "servicios" },
  "servidor": { en: "server", es: "servidor" },
  "servidores": { en: "servers", es: "servidores" },
  "dispositivo": { en: "device", es: "dispositivo" },
  "dispositivos": { en: "devices", es: "dispositivos" },
  "chave": { en: "key", es: "clave" },
  "chaves": { en: "keys", es: "claves" },
  "valor": { en: "value", es: "valor" },
  "valores": { en: "values", es: "valores" },
  "cabeçalho": { en: "header", es: "cabecera" },
  "cabeçalhos": { en: "headers", es: "cabeceras" },
  "resposta": { en: "response", es: "respuesta" },
  "respostas": { en: "responses", es: "respuestas" },
  "solicitação": { en: "request", es: "solicitud" },
  "solicitações": { en: "requests", es: "solicitudes" },
  "ambiente": { en: "environment", es: "entorno" },
  "ambientes": { en: "environments", es: "entornos" },
  "versão": { en: "version", es: "versión" },
  "versões": { en: "versions", es: "versiones" },
  "tabela": { en: "table", es: "tabla" },
  "tabelas": { en: "tables", es: "tablas" },
  "gráfico": { en: "chart", es: "gráfico" },
  "gráficos": { en: "charts", es: "gráficos" },
  "matriz": { en: "matrix", es: "matriz" },
  "matrizes": { en: "matrices", es: "matrices" },
  "mapa": { en: "map", es: "mapa" },
  "mapas": { en: "maps", es: "mapas" },
  "roteiro": { en: "roadmap", es: "hoja de ruta" },
  "roteiros": { en: "roadmaps", es: "hojas de ruta" },
  "etapa": { en: "step", es: "paso" },
  "etapas": { en: "steps", es: "pasos" },
  "passo": { en: "step", es: "paso" },
  "passos": { en: "steps", es: "pasos" },
  "fase": { en: "phase", es: "fase" },
  "fases": { en: "phases", es: "fases" },
  "item": { en: "item", es: "elemento" },
  "itens": { en: "items", es: "elementos" },
  "elemento": { en: "element", es: "elemento" },
  "elementos": { en: "elements", es: "elementos" },
  "lista": { en: "list", es: "lista" },
  "listas": { en: "lists", es: "listas" },
  "card": { en: "card", es: "tarjeta" },
  "cards": { en: "cards", es: "tarjetas" },
  "modal": { en: "modal", es: "modal" },
  "aba": { en: "tab", es: "pestaña" },
  "abas": { en: "tabs", es: "pestañas" },
  "botão": { en: "button", es: "botón" },
  "botões": { en: "buttons", es: "botones" },
  "campo": { en: "field", es: "campo" },
  "campos": { en: "fields", es: "campos" },
  "texto": { en: "text", es: "texto" },
  "textos": { en: "texts", es: "textos" },
  "exposto": { en: "exposed", es: "expuesto" },
  "exposta": { en: "exposed", es: "expuesta" },
  "expostos": { en: "exposed", es: "expuestos" },
  "expostas": { en: "exposed", es: "expuestas" },
  "pronto": { en: "ready", es: "listo" },
  "pronta": { en: "ready", es: "lista" },
  "rápido": { en: "quick", es: "rápido" },
  "rápida": { en: "quick", es: "rápida" },

  // Grammar & connectives
  "pelo": { en: "by the", es: "por el" },
  "pela": { en: "by the", es: "por la" },
  "pelos": { en: "by the", es: "por los" },
  "pelas": { en: "by the", es: "por las" },
  "sobre": { en: "about", es: "sobre" },
  "sob": { en: "under", es: "bajo" },
  "entre": { en: "between", es: "entre" },
  "contra": { en: "against", es: "contra" },
  "cada": { en: "each", es: "cada" },
  "todos": { en: "all", es: "todos" },
  "todas": { en: "all", es: "todas" },
  "todo": { en: "all", es: "todo" },
  "toda": { en: "all", es: "toda" },
  "tudo": { en: "all", es: "todo" },
  "nenhum": { en: "no", es: "ningún" },
  "nenhuma": { en: "no", es: "ninguna" },
  "algum": { en: "some", es: "algún" },
  "alguma": { en: "some", es: "alguna" },
  "alguns": { en: "some", es: "algunos" },
  "algumas": { en: "some", es: "algunas" },
  "qualquer": { en: "any", es: "cualquier" },
  "mais": { en: "more", es: "más" },
  "menos": { en: "less", es: "menos" },
  "muito": { en: "very", es: "muy" },
  "pouco": { en: "few", es: "poco" },
  "novo": { en: "new", es: "nuevo" },
  "nova": { en: "new", es: "nueva" },
  "novos": { en: "new", es: "nuevos" },
  "novas": { en: "new", es: "nuevas" },
  "último": { en: "last", es: "último" },
  "última": { en: "last", es: "última" },
  "últimos": { en: "last", es: "últimos" },
  "últimas": { en: "last", es: "últimas" },
  "primeiro": { en: "first", es: "primero" },
  "primeira": { en: "first", es: "primera" },
  "próximo": { en: "next", es: "próximo" },
  "próxima": { en: "next", es: "próxima" },
  "anterior": { en: "previous", es: "anterior" },
  "anteriores": { en: "previous", es: "anteriores" },
  "este": { en: "this", es: "este" },
  "esta": { en: "this", es: "esta" },
  "estes": { en: "these", es: "estos" },
  "estas": { en: "these", es: "estas" },
  "esse": { en: "that", es: "ese" },
  "essa": { en: "that", es: "esa" },
  "esses": { en: "those", es: "esos" },
  "essas": { en: "those", es: "esas" },
  "aquele": { en: "that", es: "aquel" },
  "aquela": { en: "that", es: "aquella" },
  "aqueles": { en: "those", es: "aquellos" },
  "aquelas": { en: "those", es: "aquellas" },
  "neste": { en: "in this", es: "en este" },
  "nesta": { en: "in this", es: "en esta" },
  "nestes": { en: "in these", es: "en estos" },
  "nestas": { en: "in these", es: "en estas" },
  "onde": { en: "where", es: "donde" },
  "quando": { en: "when", es: "cuando" },
  "como": { en: "how", es: "cómo" },
  "qual": { en: "which", es: "cuál" },
  "quais": { en: "which", es: "cuáles" },
  "quem": { en: "who", es: "quién" },
  "quanto": { en: "how much", es: "cuánto" },
  "quantos": { en: "how many", es: "cuántos" },
  "quantas": { en: "how many", es: "cuántas" },
  "porque": { en: "because", es: "porque" },
  "porquê": { en: "why", es: "por qué" },
  "não": { en: "no", es: "no" },
  "sim": { en: "yes", es: "sí" },
  "já": { en: "already", es: "ya" },
  "ainda": { en: "still", es: "todavía" },
  "sempre": { en: "always", es: "siempre" },
  "nunca": { en: "never", es: "nunca" },
  "agora": { en: "now", es: "ahora" },
  "depois": { en: "later", es: "después" },
  "antes": { en: "before", es: "antes" },
  "também": { en: "also", es: "también" },
  "apenas": { en: "only", es: "solo" },
  "somente": { en: "only", es: "solamente" }
};

export const TRANSLATIONS: Record<SupportedLanguage, Record<string, string>> = {
  pt: {
    'app.name': 'SECSCAN // AppSec & DevSecOps Platform',
    'app.tagline': 'SAST & Secret Matrix // DataFlow Taint Platform',
    'app.language': 'Idioma',
    'app.clean': 'Limpar',
    'app.restore': 'Restaurar',
    'app.export': 'Exportar',
    'app.scan_all': 'Executar Análise SAST',
    'app.scanning': 'Analisando...',
    'app.search_placeholder': 'Buscar regras, arquivos, rotas, CVEs ou pacotes...',
    'app.duration': 'Duração:',
    'app.risk_score': 'Risk Score:',

    // Categorias de Navegação
    'nav.category_all': 'Todos os Módulos',
    'nav.category_code_sast': 'Code & SAST',
    'nav.category_cloud_infra': 'Cloud & Infra',
    'nav.category_api_dast': 'API & DAST',
    'nav.category_soc_edr': 'SOC & EDR',
    'nav.category_gov_ai': 'Gov, GRC & AI',
    'nav.search_placeholder': 'Filtrar ferramentas por nome (/)...',
    'nav.domain_label': 'Domínio:',

    // Ações
    'action.commands': 'Comandos',
    'action.tutorial': 'Tutorial',
    'action.exclusions': 'Exclusões',
    'action.glossary': 'Glossário',
    'action.gitignore': '.gitignore',
    'action.export': 'Exportar',
    'action.run_scan': 'Executar Análise',

    // Abas de Ferramentas
    'tab.dashboard': 'Dashboard Executivo',
    'tab.dashboard_tooltip': 'Visão consolidada com matriz de risco e métricas executivas',
    'tab.trenddashboard': 'Tendências de Risco',
    'tab.trenddashboard_tooltip': 'Histórico e evolução do Risk Score e MTTR',
    'tab.scanner': 'Scanner SAST',
    'tab.scanner_tooltip': 'Análise estática profunda de código e detecção de segredos',
    'tab.endpoints': 'Rotas & APIs',
    'tab.endpoints_tooltip': 'Mapeamento e catalogação de rotas e endpoints de API',
    'tab.jsminer': 'JS Miner Recon',
    'tab.jsminer_tooltip': 'Mineração de bundles JS, endpoints e source maps',
    'tab.dataflow': 'Fluxo de Dados & Taint',
    'tab.dataflow_tooltip': 'Grafo interativo D3 de fluxo de variáveis e sinks',
    'tab.iast': 'IAST Runtime',
    'tab.iast_tooltip': 'Testes interativos de segurança de aplicação em tempo de execução',
    'tab.sca': 'SCA Dependências',
    'tab.sca_tooltip': 'Software Composition Analysis e inventário de CVEs',
    'tab.iac': 'IaC & Kubernetes',
    'tab.iac_tooltip': 'Auditoria de Terraform, Dockerfile e manifests K8s',
    'tab.apisecurity': 'OWASP API Top 10',
    'tab.apisecurity_tooltip': 'Inspeção de vulnerabilidades BOLA, quebra de autorização e rate limits',
    'tab.asocsla': 'ASOC & SLA MTTR',
    'tab.asocsla_tooltip': 'Gestão de conformidade com SLA e prazos de remediação',
    'tab.dast': 'DAST Fuzzer Web',
    'tab.dast_tooltip': 'Simulação de injeção dinâmica de payloads defensivos',
    'tab.sbom': 'SBOM CycloneDX',
    'tab.sbom_tooltip': 'Geração de Software Bill of Materials CycloneDX e SPDX',
    'tab.entropy': 'Entropia de Shannon',
    'tab.entropy_tooltip': 'Análise probabilística de alta entropia para chaves e credenciais',
    'tab.threatmodel': 'STRIDE Ameaças',
    'tab.threatmodel_tooltip': 'Modelagem automatizada de ameaças STRIDE e ASVS',
    'tab.ctihub': 'CTI Threat Intel',
    'tab.ctihub_tooltip': 'Feeds de inteligência de ameaças e IoCs em tempo real',
    'tab.autoremediation': 'Auto-Remediação',
    'tab.autoremediation_tooltip': 'Geração automatizada de patches unified diff',
    'tab.refactoring': 'Refatoração Segura',
    'tab.refactoring_tooltip': 'Sugestões de modernização e padrões de código seguro',
    'tab.soarbuilder': 'SOAR Playbooks',
    'tab.soarbuilder_tooltip': 'Designer visual de fluxos de resposta a incidentes',
    'tab.llmsecurity': 'OWASP LLM & AI',
    'tab.llmsecurity_tooltip': 'Segurança para modelos de linguagem e injeção de prompt',
    'tab.procyber': 'Pro Cyber Tools',
    'tab.procyber_tooltip': 'Suíte com 10 ferramentas de segurança ofensiva e defensiva',
    'tab.policyascode': 'Policy as Code (OPA)',
    'tab.policyascode_tooltip': 'Governança e quality gates baseados em Rego Open Policy Agent',
    'tab.compliance': 'Conformidade Regulatória',
    'tab.compliance_tooltip': 'Prontidão para PCI-DSS, LGPD, GDPR, HIPAA e SOC 2',
    'tab.frameworks': 'Frameworks de Segurança',
    'tab.frameworks_tooltip': 'Mapeamento NIST CSF, CIS Controls e MITRE ATT&CK',
    'tab.soccommand': 'SOC 24/7 Command Center',
    'tab.soccommand_tooltip': 'Centro de operações de segurança e correlação de alertas',
    'tab.securityonion': 'Security Onion NSM',
    'tab.securityonion_tooltip': 'Monitoramento de segurança de rede e telemetria Zeek',
    'tab.crowdstrike': 'CrowdStrike Falcon',
    'tab.crowdstrike_tooltip': 'Integração de telemetria EDR e detecções em tempo real',
    'tab.edr': 'EDR Behavioral',
    'tab.edr_tooltip': 'Regras de detecção comportamental e eBPF',
    'tab.nmap': 'Nmap Port Scanner',
    'tab.nmap_tooltip': 'Mapeamento de portas abertas e serviços de rede',
    'tab.nikto': 'Nikto Web Scanner',
    'tab.nikto_tooltip': 'Varredura de itens perigosos e versões de servidor web',
    'tab.ngfw': 'NGFW Firewall',
    'tab.ngfw_tooltip': 'Regras de inspeção de camada 7 e filtragem de pacotes',
    'tab.idsips': 'IDS/IPS Snort',
    'tab.idsips_tooltip': 'Assinaturas de detecção e prevenção de intrusão',
    'tab.dnssec': 'DNS & DNSSEC',
    'tab.dnssec_tooltip': 'Auditoria de integridade DNS, DoH e DNSSEC',
    'tab.waf': 'WAF ModSecurity',
    'tab.waf_tooltip': 'Regras de proteção web contra ataques OWASP',
    'tab.sdwan': 'SD-WAN & SASE',
    'tab.sdwan_tooltip': 'Mesh de túneis seguros e arquitetura Zero-Trust',
    'tab.headers': 'HTTP Security Headers',
    'tab.headers_tooltip': 'Auditoria de CSP, HSTS, X-Frame-Options e cabeçalhos',
    'tab.containerscan': 'Container Image Scan',
    'tab.containerscan_tooltip': 'Análise de segurança em contêineres e Dockerfiles',
    'tab.cloudiam': 'Cloud IAM Privileges',
    'tab.cloudiam_tooltip': 'Auditoria de privilégios mínimos e permissões wildcard',
    'tab.jwtinspector': 'JWT Inspector',
    'tab.jwtinspector_tooltip': 'Inspeção profunda de tokens JWT e vetores de exploração',
    'tab.ssrfvalidator': 'SSRF Validator',
    'tab.ssrfvalidator_tooltip': 'Validação de superfície de ataque e metadados de nuvem',
    'tab.rules': 'Regras Customizadas',
    'tab.rules_tooltip': 'Construtor e sandbox de expressões regulares de detecção',
    'tab.cli': 'Terminal CLI SecScan',
    'tab.cli_tooltip': 'Linha de comando interativa para automação de scans',
    'tab.pipelineflow': 'Pipeline Flow',
    'tab.pipelineflow_tooltip': 'Arquiteto visual de esteiras de segurança CI/CD',
    'tab.cicd': 'Integrações CI/CD',
    'tab.cicd_tooltip': 'Geração de templates para GitHub Actions, GitLab e Azure'
  },
  en: {
    'app.name': 'SECSCAN // AppSec & DevSecOps Platform',
    'app.tagline': 'SAST & Secret Matrix // DataFlow Taint Platform',
    'app.language': 'Language',
    'app.clean': 'Clear',
    'app.restore': 'Restore Demo',
    'app.export': 'Export',
    'app.scan_all': 'Run SAST Analysis',
    'app.scanning': 'Analyzing...',
    'app.search_placeholder': 'Search rules, files, routes, CVEs or packages...',
    'app.duration': 'Duration:',
    'app.risk_score': 'Risk Score:',

    // Navigation categories
    'nav.category_all': 'All Modules',
    'nav.category_code_sast': 'Code & SAST',
    'nav.category_cloud_infra': 'Cloud & Infra',
    'nav.category_api_dast': 'API & DAST',
    'nav.category_soc_edr': 'SOC & EDR',
    'nav.category_gov_ai': 'Gov, GRC & AI',
    'nav.search_placeholder': 'Filter tools by name (/)...',
    'nav.domain_label': 'Domain:',

    // Actions
    'action.commands': 'Commands',
    'action.tutorial': 'Tutorial',
    'action.exclusions': 'Exclusions',
    'action.glossary': 'Glossary',
    'action.gitignore': '.gitignore',
    'action.export': 'Export',
    'action.run_scan': 'Run Scan',

    // Tool tabs
    'tab.dashboard': 'Executive Dashboard',
    'tab.dashboard_tooltip': 'Consolidated view with risk matrix and executive metrics',
    'tab.trenddashboard': 'Risk Trends',
    'tab.trenddashboard_tooltip': 'Historical evolution of Risk Score and MTTR',
    'tab.scanner': 'SAST Scanner',
    'tab.scanner_tooltip': 'Deep static code analysis and secret exposure detection',
    'tab.endpoints': 'Routes & APIs',
    'tab.endpoints_tooltip': 'API endpoints mapping and LinkFinder reconnaissance',
    'tab.jsminer': 'JS Miner Recon',
    'tab.jsminer_tooltip': 'Mining of JS bundles, API routes and source maps',
    'tab.dataflow': 'Data Flow & Taint',
    'tab.dataflow_tooltip': 'Interactive D3 taint flow graph from sources to sinks',
    'tab.iast': 'IAST Runtime',
    'tab.iast_tooltip': 'Interactive application security testing at runtime',
    'tab.sca': 'SCA Packages',
    'tab.sca_tooltip': 'Software Composition Analysis and CVE inventory',
    'tab.iac': 'IaC & Kubernetes',
    'tab.iac_tooltip': 'Terraform, Dockerfile and K8s configuration audit',
    'tab.apisecurity': 'OWASP API Top 10',
    'tab.apisecurity_tooltip': 'API security inspection for BOLA, broken auth, rate limits',
    'tab.asocsla': 'ASOC & SLA MTTR',
    'tab.asocsla_tooltip': 'SLA compliance management and remediation deadlines',
    'tab.dast': 'DAST Web Fuzzer',
    'tab.dast_tooltip': 'Dynamic simulation of defensive fuzzing payloads',
    'tab.sbom': 'SBOM CycloneDX',
    'tab.sbom_tooltip': 'CycloneDX and SPDX Software Bill of Materials generator',
    'tab.entropy': 'Shannon Entropy',
    'tab.entropy_tooltip': 'Shannon entropy probabilistic analysis for high-entropy secrets',
    'tab.threatmodel': 'STRIDE Threats',
    'tab.threatmodel_tooltip': 'Automated STRIDE and ASVS threat modeling',
    'tab.ctihub': 'CTI Threat Intel',
    'tab.ctihub_tooltip': 'Real-time cyber threat intelligence and IoC feeds',
    'tab.autoremediation': 'Auto-Remediation',
    'tab.autoremediation_tooltip': 'Unified diff remediation patch generator',
    'tab.refactoring': 'Secure Refactoring',
    'tab.refactoring_tooltip': 'Modernization suggestions and secure code patterns',
    'tab.soarbuilder': 'SOAR Playbooks',
    'tab.soarbuilder_tooltip': 'Visual incident response workflow designer',
    'tab.llmsecurity': 'OWASP LLM & AI',
    'tab.llmsecurity_tooltip': 'Large Language Model security and prompt injection guardrails',
    'tab.procyber': 'Pro Cyber Tools',
    'tab.procyber_tooltip': 'Suite of 10 professional offensive and defensive tools',
    'tab.policyascode': 'Policy as Code (OPA)',
    'tab.policyascode_tooltip': 'Rego-based Open Policy Agent CI/CD quality gates',
    'tab.compliance': 'Regulatory Compliance',
    'tab.compliance_tooltip': 'PCI-DSS, LGPD, GDPR, HIPAA and SOC 2 readiness audit',
    'tab.frameworks': 'Security Frameworks',
    'tab.frameworks_tooltip': 'NIST CSF, CIS Controls and MITRE ATT&CK mapping',
    'tab.soccommand': 'SOC 24/7 Command Center',
    'tab.soccommand_tooltip': 'Security operations center and event correlation',
    'tab.securityonion': 'Security Onion NSM',
    'tab.securityonion_tooltip': 'Network security monitoring and Zeek telemetry',
    'tab.crowdstrike': 'CrowdStrike Falcon',
    'tab.crowdstrike_tooltip': 'EDR telemetry integration and real-time detections',
    'tab.edr': 'EDR Behavioral',
    'tab.edr_tooltip': 'Behavioral detection rules and eBPF tracing',
    'tab.nmap': 'Nmap Port Scanner',
    'tab.nmap_tooltip': 'Open port and network service discovery',
    'tab.nikto': 'Nikto Web Scanner',
    'tab.nikto_tooltip': 'Web server misconfiguration and version scanner',
    'tab.ngfw': 'NGFW Firewall',
    'tab.ngfw_tooltip': 'Layer-7 traffic inspection and packet filtering rules',
    'tab.idsips': 'IDS/IPS Snort',
    'tab.idsips_tooltip': 'Intrusion detection and prevention signatures',
    'tab.dnssec': 'DNS & DNSSEC',
    'tab.dnssec_tooltip': 'DNS integrity, DoH and DNSSEC audit',
    'tab.waf': 'WAF ModSecurity',
    'tab.waf_tooltip': 'Web application firewall rules against OWASP attacks',
    'tab.sdwan': 'SD-WAN & SASE',
    'tab.sdwan_tooltip': 'Secure tunnel mesh and Zero-Trust architecture',
    'tab.headers': 'HTTP Security Headers',
    'tab.headers_tooltip': 'Audit of CSP, HSTS, X-Frame-Options and headers',
    'tab.containerscan': 'Container Image Scan',
    'tab.containerscan_tooltip': 'Container image security and Dockerfile CIS audit',
    'tab.cloudiam': 'Cloud IAM Privileges',
    'tab.cloudiam_tooltip': 'Least-privilege audit and wildcard permissions detector',
    'tab.jwtinspector': 'JWT Inspector',
    'tab.jwtinspector_tooltip': 'Deep JWT token inspection and algorithm exploit analyzer',
    'tab.ssrfvalidator': 'SSRF Validator',
    'tab.ssrfvalidator_tooltip': 'SSRF attack surface and cloud metadata validator',
    'tab.rules': 'Custom Rules',
    'tab.rules_tooltip': 'Regex rule builder and detection unit test library',
    'tab.cli': 'SecScan CLI Terminal',
    'tab.cli_tooltip': 'Interactive command line for scan automation',
    'tab.pipelineflow': 'Pipeline Flow',
    'tab.pipelineflow_tooltip': 'Visual CI/CD security pipeline architect',
    'tab.cicd': 'CI/CD Integrations',
    'tab.cicd_tooltip': 'Ready-to-use templates for GitHub Actions, GitLab and Azure'
  },
  es: {
    'app.name': 'SECSCAN // AppSec & DevSecOps Platform',
    'app.tagline': 'SAST & Secret Matrix // Plataforma DataFlow Taint',
    'app.language': 'Idioma',
    'app.clean': 'Limpiar',
    'app.restore': 'Restaurar Demo',
    'app.export': 'Exportar',
    'app.scan_all': 'Ejecutar Análisis SAST',
    'app.scanning': 'Analizando...',
    'app.search_placeholder': 'Buscar reglas, archivos, rutas, CVEs o paquetes...',
    'app.duration': 'Duración:',
    'app.risk_score': 'Puntaje de Riesgo:',

    // Categorías de Navegación
    'nav.category_all': 'Todos los Módulos',
    'nav.category_code_sast': 'Código y SAST',
    'nav.category_cloud_infra': 'Nube e Infra',
    'nav.category_api_dast': 'API y DAST',
    'nav.category_soc_edr': 'SOC y EDR',
    'nav.category_gov_ai': 'Gov, GRC e IA',
    'nav.search_placeholder': 'Filtrar herramientas por nombre (/)...',
    'nav.domain_label': 'Dominio:',

    // Acciones
    'action.commands': 'Comandos',
    'action.tutorial': 'Tutorial',
    'action.exclusions': 'Exclusiones',
    'action.glossary': 'Glosario',
    'action.gitignore': '.gitignore',
    'action.export': 'Exportar',
    'action.run_scan': 'Ejecutar Análisis',

    // Pestañas
    'tab.dashboard': 'Tablero Ejecutivo',
    'tab.dashboard_tooltip': 'Vista consolidada con matriz de riesgo y métricas ejecutivas',
    'tab.trenddashboard': 'Tendencias de Riesgo',
    'tab.trenddashboard_tooltip': 'Evolución histórica de Risk Score y MTTR',
    'tab.scanner': 'Escáner SAST',
    'tab.scanner_tooltip': 'Análisis estático profundo de código y detección de secretos',
    'tab.endpoints': 'Rutas y APIs',
    'tab.endpoints_tooltip': 'Mapeo y catalogación de rutas y endpoints de API',
    'tab.jsminer': 'JS Miner Recon',
    'tab.jsminer_tooltip': 'Minería de paquetes JS, rutas de API y mapas de origen',
    'tab.dataflow': 'Flujo de Datos y Taint',
    'tab.dataflow_tooltip': 'Grafo interactivo D3 de flujo de variables y sumideros',
    'tab.iast': 'IAST Runtime',
    'tab.iast_tooltip': 'Pruebas interactivas de seguridad de aplicaciones en tiempo de ejecución',
    'tab.sca': 'SCA Dependencias',
    'tab.sca_tooltip': 'Software Composition Analysis e inventario de CVEs',
    'tab.iac': 'IaC y Kubernetes',
    'tab.iac_tooltip': 'Auditoría de Terraform, Dockerfile y manifiestos de K8s',
    'tab.apisecurity': 'OWASP API Top 10',
    'tab.apisecurity_tooltip': 'Inspección de vulnerabilidades BOLA, autorización rota y límites de tasa',
    'tab.asocsla': 'ASOC y SLA MTTR',
    'tab.asocsla_tooltip': 'Gestión de cumplimiento de SLA y plazos de remediación',
    'tab.dast': 'DAST Fuzzer Web',
    'tab.dast_tooltip': 'Simulación de inyección dinámica de cargas defensivas',
    'tab.sbom': 'SBOM CycloneDX',
    'tab.sbom_tooltip': 'Generación de Software Bill of Materials CycloneDX y SPDX',
    'tab.entropy': 'Entropía de Shannon',
    'tab.entropy_tooltip': 'Análisis probabilístico de alta entropía para claves y credenciales',
    'tab.threatmodel': 'STRIDE Amenazas',
    'tab.threatmodel_tooltip': 'Modelado automatizado de amenazas STRIDE y ASVS',
    'tab.ctihub': 'CTI Threat Intel',
    'tab.ctihub_tooltip': 'Feeds de inteligencia de amenazas e IoCs en tiempo real',
    'tab.autoremediation': 'Auto-Remediación',
    'tab.autoremediation_tooltip': 'Generador de parches de remediación unified diff',
    'tab.refactoring': 'Refactorización Segura',
    'tab.refactoring_tooltip': 'Sugerencias de modernización y patrones de código seguro',
    'tab.soarbuilder': 'SOAR Playbooks',
    'tab.soarbuilder_tooltip': 'Diseñador visual de flujos de respuesta a incidentes',
    'tab.llmsecurity': 'OWASP LLM e IA',
    'tab.llmsecurity_tooltip': 'Seguridad para modelos de lenguaje e inyección de prompts',
    'tab.procyber': 'Pro Cyber Tools',
    'tab.procyber_tooltip': 'Suite con 10 herramientas profesionales ofensivas y defensivas',
    'tab.policyascode': 'Policy as Code (OPA)',
    'tab.policyascode_tooltip': 'Gobernanza y quality gates basados en Rego Open Policy Agent',
    'tab.compliance': 'Cumplimiento Regulatorio',
    'tab.compliance_tooltip': 'Auditoría de preparación para PCI-DSS, LGPD, GDPR, HIPAA y SOC 2',
    'tab.frameworks': 'Frameworks de Seguridad',
    'tab.frameworks_tooltip': 'Mapeo NIST CSF, CIS Controls y MITRE ATT&CK',
    'tab.soccommand': 'SOC 24/7 Command Center',
    'tab.soccommand_tooltip': 'Centro de operaciones de seguridad y correlación de alertas',
    'tab.securityonion': 'Security Onion NSM',
    'tab.securityonion_tooltip': 'Monitoreo de seguridad de red y telemetría Zeek',
    'tab.crowdstrike': 'CrowdStrike Falcon',
    'tab.crowdstrike_tooltip': 'Integración de telemetría EDR y detecciones en tiempo real',
    'tab.edr': 'EDR Behavioral',
    'tab.edr_tooltip': 'Reglas de detección conductual y eBPF',
    'tab.nmap': 'Escáner Nmap',
    'tab.nmap_tooltip': 'Mapeo de puertos abiertos y servicios de red',
    'tab.nikto': 'Nikto Web Scanner',
    'tab.nikto_tooltip': 'Escaneo de configuraciones incorrectas y versiones web',
    'tab.ngfw': 'NGFW Firewall',
    'tab.ngfw_tooltip': 'Inspección de capa 7 y reglas de filtrado de paquetes',
    'tab.idsips': 'IDS/IPS Snort',
    'tab.idsips_tooltip': 'Firmas de detección y prevención de intrusiones',
    'tab.dnssec': 'DNS y DNSSEC',
    'tab.dnssec_tooltip': 'Auditoría de integridad DNS, DoH y DNSSEC',
    'tab.waf': 'WAF ModSecurity',
    'tab.waf_tooltip': 'Reglas de firewall de aplicaciones web contra ataques OWASP',
    'tab.sdwan': 'SD-WAN y SASE',
    'tab.sdwan_tooltip': 'Malla de túneles seguros y arquitectura Zero-Trust',
    'tab.headers': 'Encabezados HTTP',
    'tab.headers_tooltip': 'Auditoría de CSP, HSTS, X-Frame-Options y encabezados',
    'tab.containerscan': 'Escaneo de Contenedores',
    'tab.containerscan_tooltip': 'Seguridad de imágenes de contenedor y auditoría CIS Dockerfile',
    'tab.cloudiam': 'Cloud IAM Privileges',
    'tab.cloudiam_tooltip': 'Auditoría de privilegios mínimos y permisos comodín',
    'tab.jwtinspector': 'Inspector JWT',
    'tab.jwtinspector_tooltip': 'Inspección profunda de tokens JWT y análisis de vulnerabilidades',
    'tab.ssrfvalidator': 'Validador SSRF',
    'tab.ssrfvalidator_tooltip': 'Validación de superficie de ataque y metadatos de nube',
    'tab.rules': 'Reglas Personalizadas',
    'tab.rules_tooltip': 'Constructor y sandbox de expresiones regulares de detección',
    'tab.cli': 'Terminal CLI SecScan',
    'tab.cli_tooltip': 'Línea de comando interactiva para automatización de análisis',
    'tab.pipelineflow': 'Pipeline Flow',
    'tab.pipelineflow_tooltip': 'Arquitecto visual de canalizaciones de seguridad CI/CD',
    'tab.cicd': 'Integraciones CI/CD',
    'tab.cicd_tooltip': 'Plantillas listas para usar en GitHub Actions, GitLab y Azure'
  }
};

interface LanguageContextType {
  language: SupportedLanguage;
  setLanguage: (lang: SupportedLanguage) => void;
  currentLanguageInfo: LanguageInfo;
  t: (key: string, params?: Record<string, string | number>, defaultText?: string) => string;
  translateText: (text: string, targetLanguage?: SupportedLanguage) => string;
  lastChangedToast: string | null;
  clearToast: () => void;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

// Preservation maps
const originalTextNodeMap = new WeakMap<Node, string>();
const originalAttrMap = new WeakMap<Element, Record<string, string>>();

function escapeRegex(s: string): string {
  return s.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
}

function matchCase(source: string, replacement: string): string {
  if (!source || !replacement || typeof source !== 'string' || typeof replacement !== 'string') {
    return replacement || source || '';
  }
  if (source === source.toUpperCase() && source !== source.toLowerCase()) {
    return replacement.toUpperCase();
  }
  if (source[0] && source[0] === source[0].toUpperCase() && (!source[1] || source[1] === source[1]?.toLowerCase())) {
    return (replacement[0] ? replacement[0].toUpperCase() : '') + replacement.slice(1);
  }
  return replacement;
}

// Protected technical terms regex to prevent any translation or alteration of acronyms and tooling
const TECHNICAL_TERMS_REGEX = /\b(DoS|DDoS|SAST|DAST|IAST|SCA|IaC|SOC|EDR|SIEM|WAF|NGFW|IDS|IPS|DPI|DNS|DNSSEC|DoH|SD-WAN|SDWAN|SASE|JWT|SSRF|BOLA|BFLA|XSS|CSRF|SQLi|RCE|CORS|CSP|HSTS|CVE|CVEs|CVSS|CWE|SBOM|CycloneDX|SPDX|STRIDE|ASOC|MTTR|SLA|SLAs|OPA|Rego|REGO|REST|API|APIs|GraphQL|gRPC|HTML|JSON|CSV|PDF|SARIF|CLI|eBPF|Zeek|Snort|Suricata|Docker|Kubernetes|K8s|Falcon|CrowdStrike|Nikto|Nmap|GitHub|GitLab|Azure|AWS|GCP|Linux|Windows|macOS|OS|Node|NodeJS|TypeScript|JavaScript|SHA256|SHA1|MD5|AES|RSA|TLS|SSL|SSH|VPN|IP|IPs|TCP|UDP|HTTP|HTTPS|URL|URI|URN|UUID|OAuth|IAM|RBAC|ABAC|PCI-DSS|LGPD|GDPR|HIPAA|SOC2|CIS|MITRE|OWASP|NIST|CSF|ASVS|SecScan|AppSec|DevSecOps)\b/g;

// Dangerous short words that MUST NOT be replaced in single-word translation (avoids colliding with English 'a', 'as', 'do', 'no', 'os', 'dos', etc.)
const UNSAFE_SHORT_WORDS = new Set([
  'a', 'as', 'e', 'o', 'os', 'no', 'do', 'dos', 'da', 'das',
  'na', 'nas', 'nos', 'em', 'de', 'se', 'me', 'so', 'or',
  'in', 'is', 'it', 'at', 'to', 'by', 'on', 'if', 'up', 'us'
]);

// Pre-compiled regex entries for fast execution of Phase 1
export const COMPILED_PHRASES = PHRASE_DICTIONARY.map(([pt, en, es]) => ({
  regex: new RegExp(escapeRegex(pt), 'gi'),
  en,
  es
}));

// Two-phase translation: Phase 1 (Compound phrases protected via tokens) + Phase 1.5 (Technical terms protection) + Phase 2 (Word replacement)
export function translateString(str: string, targetLang: SupportedLanguage): string {
  if (targetLang === 'pt' || !str || typeof str !== 'string') return str;
  let res = str;
  const tokens: string[] = [];

  // Step 1: Compound phrases (longest first, preserved via token placeholders)
  for (let i = 0; i < COMPILED_PHRASES.length; i++) {
    const item = COMPILED_PHRASES[i];
    const repl = targetLang === 'en' ? item.en : item.es;
    item.regex.lastIndex = 0;
    if (item.regex.test(res)) {
      item.regex.lastIndex = 0;
      res = res.replace(item.regex, (matched) => {
        const idx = tokens.length;
        tokens.push(matchCase(matched, repl));
        return `\uE000${idx}\uE001`;
      });
    }
  }

  // Step 1.5: Protect standalone technical acronyms & proper nouns that were not part of compound phrases
  res = res.replace(TECHNICAL_TERMS_REGEX, (matched) => {
    const idx = tokens.length;
    tokens.push(matched);
    return `\uE000${idx}\uE001`;
  });

  // Step 2: Safe Word-level replacement for Portuguese words
  res = res.replace(/[a-zA-ZáàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]+/g, (word) => {
    const lower = word.toLowerCase();
    if (UNSAFE_SHORT_WORDS.has(lower)) {
      return word;
    }
    if (Object.prototype.hasOwnProperty.call(WORD_DICTIONARY, lower)) {
      const entry = WORD_DICTIONARY[lower];
      if (entry && typeof entry === 'object') {
        const repl = targetLang === 'en' ? entry.en : entry.es;
        if (typeof repl === 'string') {
          return matchCase(word, repl);
        }
      }
    }
    return word;
  });

  // Step 3: Restore protected compound phrase tokens & technical terms
  if (tokens.length > 0) {
    res = res.replace(/\uE000(\d+)\uE001/g, (_, idx) => tokens[Number(idx)]);
  }

  return res;
}

export interface LanguageProviderProps {
  children: ReactNode;
}

export const LanguageProvider: React.FC<LanguageProviderProps> = ({ children }) => {
  const [language, setLanguageState] = useState<SupportedLanguage>(() => {
    const saved = safeGetItem('secscan_language') as SupportedLanguage;
    if (saved && (saved === 'pt' || saved === 'en' || saved === 'es')) {
      return saved;
    }
    if (typeof navigator !== 'undefined' && navigator.language) {
      const navLang = navigator.language.toLowerCase();
      if (navLang.startsWith('en')) return 'en';
      if (navLang.startsWith('es')) return 'es';
    }
    return 'pt';
  });

  const [lastChangedToast, setLastChangedToast] = useState<string | null>(null);
  const originalTitleRef = useRef<string>('');

  const clearToast = () => setLastChangedToast(null);

  const currentLanguageInfo = useMemo(() => {
    return SUPPORTED_LANGUAGES.find(l => l.code === language) || SUPPORTED_LANGUAGES[0];
  }, [language]);

  const performDomWalk = (targetLang: SupportedLanguage) => {
    if (typeof document === 'undefined') return;
    try {
      const root = document.getElementById('root') || document.body;
      if (!root) return;

      // 1. Walk Text Nodes
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
      let node = walker.nextNode() as Text | null;
      while (node) {
        try {
          const parent = node.parentElement;
          if (parent) {
            // Strictly skip code blocks, syntax highlighters, scripts, and marked areas
            if (!parent.closest('pre, code, kbd, script, style, noscript, textarea, .prism-code, .monaco-editor, #code-snippet-pre, [data-no-translate="true"]')) {
              const currentVal = node.nodeValue;
              if (currentVal && currentVal.trim()) {
                // Store pristine original text directly on the node instance
                let originalVal = (node as any).__origPtText || originalTextNodeMap.get(node);
                if (!originalVal) {
                  originalVal = currentVal;
                  (node as any).__origPtText = originalVal;
                  originalTextNodeMap.set(node, originalVal);
                }

                if (targetLang === 'pt') {
                  if (node.nodeValue !== originalVal) {
                    node.nodeValue = originalVal;
                  }
                } else {
                  const translated = translateString(originalVal, targetLang);
                  if (translated && node.nodeValue !== translated) {
                    node.nodeValue = translated;
                  }
                }
              }
            }
          }
        } catch {
          // Gracefully continue to next node if any error occurs on a specific node
        }
        node = walker.nextNode() as Text | null;
      }

      // 2. Walk Element Attributes: title, placeholder, aria-label
      const elements = root.querySelectorAll('[title], [placeholder], [aria-label]');
      for (let i = 0; i < elements.length; i++) {
        try {
          const el = elements[i];
          if (el.closest('pre, code, kbd, script, style, noscript, textarea, .prism-code, .monaco-editor, #code-snippet-pre, [data-no-translate="true"]')) continue;

          let stored = (el as any).__origAttrs || originalAttrMap.get(el);
          if (!stored) {
            stored = {};
            if (el.hasAttribute('title')) stored.title = el.getAttribute('title') || '';
            if (el.hasAttribute('placeholder')) stored.placeholder = el.getAttribute('placeholder') || '';
            if (el.hasAttribute('aria-label')) stored['aria-label'] = el.getAttribute('aria-label') || '';
            (el as any).__origAttrs = stored;
            originalAttrMap.set(el, stored);
          }

          const attrs = ['title', 'placeholder', 'aria-label'] as const;
          for (let j = 0; j < attrs.length; j++) {
            const attr = attrs[j];
            if (stored[attr] !== undefined && stored[attr].trim()) {
              const original = stored[attr];
              if (targetLang === 'pt') {
                if (el.getAttribute(attr) !== original) {
                  el.setAttribute(attr, original);
                }
              } else {
                const translated = translateString(original, targetLang);
                if (translated && el.getAttribute(attr) !== translated) {
                  el.setAttribute(attr, translated);
                }
              }
            }
          }
        } catch {
          // Gracefully continue to next element
        }
      }

      // 3. Document Title
      if (typeof document !== 'undefined' && document.title) {
        if (!originalTitleRef.current) {
          originalTitleRef.current = document.title;
        }
        if (targetLang === 'pt') {
          if (document.title !== originalTitleRef.current) {
            document.title = originalTitleRef.current;
          }
        } else {
          const translatedTitle = translateString(originalTitleRef.current, targetLang);
          if (document.title !== translatedTitle) {
            document.title = translatedTitle;
          }
        }
      }
    } catch (err) {
      console.error('performDomWalk error:', err);
    }
  };

  const setLanguage = (newLang: SupportedLanguage) => {
    if (newLang === language) return;
    setLanguageState(newLang);
    safeSetItem('secscan_language', newLang);
    if (typeof document !== 'undefined') {
      document.documentElement.lang = newLang;
    }
    const info = SUPPORTED_LANGUAGES.find(l => l.code === newLang) || SUPPORTED_LANGUAGES[0];
    const toastMsg = newLang === 'en' 
      ? `✓ Language switched to: ${info.name} ${info.flag}`
      : newLang === 'es'
      ? `✓ Idioma cambiado a: ${info.name} ${info.flag}`
      : `✓ Idioma alterado para: ${info.name} ${info.flag}`;
    setLastChangedToast(toastMsg);
    setTimeout(() => {
      setLastChangedToast(prev => (prev === toastMsg ? null : prev));
    }, 3500);

    // Run DOM walk immediately
    setTimeout(() => {
      performDomWalk(newLang);
    }, 10);

    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('secscan-language-changed', { detail: newLang }));
    }
  };

  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = language;
    }
  }, [language]);

  // Real-time DOM Text Walker & MutationObserver
  useEffect(() => {
    if (typeof document === 'undefined') return;

    performDomWalk(language);

    // Run slightly delayed pass to ensure newly rendered views are caught
    const timer = setTimeout(() => {
      performDomWalk(language);
    }, 100);

    let isApplying = false;
    let timeoutId: any = null;
    const observer = new MutationObserver((mutations) => {
      if (isApplying) return;
      let hasInterestingMutation = false;
      for (const m of mutations) {
        if (m.type === 'childList' && m.addedNodes.length > 0) {
          hasInterestingMutation = true;
          break;
        }
      }

      if (hasInterestingMutation) {
        if (timeoutId) clearTimeout(timeoutId);
        timeoutId = setTimeout(() => {
          isApplying = true;
          try {
            performDomWalk(language);
          } finally {
            isApplying = false;
          }
        }, 40);
      }
    });

    const targetEl = document.getElementById('root') || document.body;
    observer.observe(targetEl, {
      childList: true,
      subtree: true
    });

    return () => {
      clearTimeout(timer);
      observer.disconnect();
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [language]);

  const t = (key: string, params?: Record<string, string | number>, defaultText?: string): string => {
    const langDict = TRANSLATIONS[language] || TRANSLATIONS.pt;
    let text = langDict[key] || TRANSLATIONS.en[key] || TRANSLATIONS.pt[key];

    if (!text) {
      const fallback = defaultText || key;
      text = language === 'pt' ? fallback : translateString(fallback, language);
    }

    if (params) {
      Object.entries(params).forEach(([paramKey, val]) => {
        text = text.replace(new RegExp(`\\{${paramKey}\\}`, 'g'), String(val));
      });
    }

    return text;
  };

  const translateText = (text: string, targetLanguage?: SupportedLanguage): string => {
    const tgt = targetLanguage || language;
    return translateString(text, tgt);
  };

  return (
    <LanguageContext.Provider value={{ language, setLanguage, currentLanguageInfo, t, translateText, lastChangedToast, clearToast }}>
      {children}
      {/* Global floating toast notification on language switch */}
      {lastChangedToast && (
        <div 
          id="secscan-language-toast"
          className="fixed bottom-6 right-6 z-[9999] bg-[#0C0C0E] border-2 border-[#00FF41] text-white px-4 py-3 rounded-lg shadow-[0_0_25px_rgba(0,255,65,0.35)] flex items-center gap-3 font-mono text-xs animate-in slide-in-from-bottom-5 duration-200 backdrop-blur-md select-none"
        >
          <div className="w-2.5 h-2.5 rounded-full bg-[#00FF41] animate-ping" />
          <span className="font-bold text-[#00FF41] tracking-wide">{lastChangedToast}</span>
          <button 
            type="button"
            onClick={clearToast}
            className="ml-2 text-zinc-400 hover:text-white text-sm font-bold cursor-pointer"
            title="Fechar"
          >
            ×
          </button>
        </div>
      )}
    </LanguageContext.Provider>
  );
};

export const useLanguage = (): LanguageContextType => {
  const context = useContext(LanguageContext);
  if (!context) {
    return {
      language: 'pt',
      setLanguage: () => {},
      currentLanguageInfo: SUPPORTED_LANGUAGES[0],
      t: (key: string, _params?: any, defaultText?: string) => defaultText || key,
      translateText: (text: string) => text,
      lastChangedToast: null,
      clearToast: () => {}
    };
  }
  return context;
};
