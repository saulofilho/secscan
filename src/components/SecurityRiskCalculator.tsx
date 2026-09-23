import React, { useState, useMemo, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Server, 
  Globe, 
  Lock, 
  Flame, 
  Cpu, 
  Layers, 
  CheckCircle2, 
  AlertTriangle, 
  RotateCcw, 
  Sliders, 
  Info, 
  FileCode, 
  Terminal, 
  KeyRound, 
  Activity, 
  ArrowRight, 
  Sparkles, 
  Copy, 
  Check, 
  Shield, 
  ExternalLink 
} from 'lucide-react';
import { ScanReport, ScanFinding, SeverityLevel } from '../types';
import { safeGetItem, safeSetItem } from '../lib/storage';

export type EnvironmentExposure = 'PUBLIC_INTERNET' | 'INTERNAL_VPC' | 'AIR_GAPPED';
export type DataSensitivity = 'HIGH_REGULATED' | 'BUSINESS_CONFIDENTIAL' | 'PUBLIC_TELEMETRY';
export type IngressProtection = 'NONE_DIRECT' | 'WAF_RATE_LIMIT' | 'ZERO_TRUST_MTLS';
export type AuthRequirement = 'ANONYMOUS_PUBLIC' | 'JWT_SESSION_AUTH' | 'MFA_RBAC_STRICT';
export type NodeFramework = 'EXPRESS' | 'NESTJS' | 'NEXTJS' | 'FASTIFY' | 'VANILLA_NODE';
export type NodeVersionTier = 'NODE_20_22_LTS' | 'NODE_18_LTS' | 'NODE_LEGACY_EOL';

export interface RiskCalculatorConfig {
  exposure: EnvironmentExposure;
  dataSensitivity: DataSensitivity;
  ingress: IngressProtection;
  auth: AuthRequirement;
  framework: NodeFramework;
  tsStrict: boolean;
  nodeVersion: NodeVersionTier;
  helmetEnabled: boolean;
  inputValidationEnabled: boolean;
}

const DEFAULT_CALCULATOR_CONFIG: RiskCalculatorConfig = {
  exposure: 'PUBLIC_INTERNET',
  dataSensitivity: 'HIGH_REGULATED',
  ingress: 'NONE_DIRECT',
  auth: 'ANONYMOUS_PUBLIC',
  framework: 'EXPRESS',
  tsStrict: true,
  nodeVersion: 'NODE_20_22_LTS',
  helmetEnabled: false,
  inputValidationEnabled: false
};

const STORAGE_KEY = 'secscan_security_risk_calculator_v1';

interface SecurityRiskCalculatorProps {
  report: ScanReport;
  findings?: ScanFinding[];
  onNavigateToScanner?: () => void;
  onSelectFinding?: (finding: ScanFinding) => void;
}

export const SecurityRiskCalculator: React.FC<SecurityRiskCalculatorProps> = ({
  report,
  findings: externalFindings,
  onNavigateToScanner,
  onSelectFinding
}) => {
  const findings = externalFindings || report.findings || [];

  // Load configuration from local storage with fallback
  const [config, setConfig] = useState<RiskCalculatorConfig>(() => {
    try {
      const saved = safeGetItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        return { ...DEFAULT_CALCULATOR_CONFIG, ...parsed };
      }
    } catch {
      // ignore
    }
    return DEFAULT_CALCULATOR_CONFIG;
  });

  const [copiedSummary, setCopiedSummary] = useState(false);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'BREAKDOWN' | 'SIMULATOR' | 'HARDENING'>('OVERVIEW');

  // Persist config changes
  useEffect(() => {
    try {
      safeSetItem(STORAGE_KEY, JSON.stringify(config));
    } catch {
      // ignore
    }
  }, [config]);

  // 1. Analyze Findings for Node/TS Specific Threats
  const stackFindingStats = useMemo(() => {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    let nodeRceCount = 0;
    let protoPollutionCount = 0;
    let pathTraversalCount = 0;
    let reDosCount = 0;
    let secretsCount = 0;
    let ssrfCount = 0;

    findings.forEach(f => {
      if (f.severity === 'CRITICAL') criticalCount++;
      else if (f.severity === 'HIGH') highCount++;
      else if (f.severity === 'MEDIUM') mediumCount++;
      else if (f.severity === 'LOW') lowCount++;

      const ruleLower = (f.ruleName + ' ' + (f.snippet || '')).toLowerCase();

      // Node command execution / eval
      if (ruleLower.includes('child_process') || ruleLower.includes('exec') || ruleLower.includes('eval(') || ruleLower.includes('rce') || ruleLower.includes('command injection')) {
        nodeRceCount++;
      }
      // Prototype pollution
      if (ruleLower.includes('__proto__') || ruleLower.includes('constructor.prototype') || ruleLower.includes('prototype pollution') || ruleLower.includes('merge')) {
        protoPollutionCount++;
      }
      // Path traversal
      if (ruleLower.includes('path traversal') || ruleLower.includes('path.join') || ruleLower.includes('readfile') || ruleLower.includes('../')) {
        pathTraversalCount++;
      }
      // ReDoS in V8
      if (ruleLower.includes('redos') || ruleLower.includes('catastrophic') || ruleLower.includes('exponential')) {
        reDosCount++;
      }
      // Secrets / API keys
      if (f.category === 'API_KEY' || f.category === 'AUTH_TOKEN' || f.category === 'CLOUD_CREDENTIAL' || f.category === 'PRIVATE_KEY' || f.category === 'PASSWORD') {
        secretsCount++;
      }
      // SSRF
      if (ruleLower.includes('ssrf') || ruleLower.includes('axios') || ruleLower.includes('fetch')) {
        ssrfCount++;
      }
    });

    return {
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      totalCount: findings.length,
      nodeRceCount,
      protoPollutionCount,
      pathTraversalCount,
      reDosCount,
      secretsCount,
      ssrfCount
    };
  }, [findings]);

  // 2. Multipliers & Weights Calculation
  const calculation = useMemo(() => {
    // 2A. Raw Finding Base Load (Scaled 0 - 100 based on severity)
    // A single critical is worth 25 pts, High 12 pts, Med 4 pts, Low 1 pt
    const rawFindingPoints = (stackFindingStats.criticalCount * 26) +
      (stackFindingStats.highCount * 13) +
      (stackFindingStats.mediumCount * 4) +
      (stackFindingStats.lowCount * 1);

    // Normalize base points to a 0-60 baseline before contextual multipliers
    const baseFindingLoad = Math.min(65, Math.round(rawFindingPoints * 0.8));

    // 2B. Node/TS Stack Factor
    // Node.js is single-threaded; RCE or ReDoS blocks or compromises the entire runtime
    let stackMultiplier = 1.0;
    if (stackFindingStats.nodeRceCount > 0) stackMultiplier += 0.35;
    if (stackFindingStats.protoPollutionCount > 0) stackMultiplier += 0.25;
    if (stackFindingStats.reDosCount > 0) stackMultiplier += 0.20;
    if (stackFindingStats.secretsCount > 0) stackMultiplier += 0.20;
    if (stackFindingStats.pathTraversalCount > 0) stackMultiplier += 0.15;
    if (stackFindingStats.ssrfCount > 0) stackMultiplier += 0.15;

    // Node Framework baseline adjustment
    const frameworkAdjustments: Record<NodeFramework, number> = {
      EXPRESS: 1.05,     // Minimalist, requires manual middleware for security
      FASTIFY: 0.95,     // Built-in schema validation & high performance
      NESTJS: 0.90,      // Enterprise decorators, built-in validation pipes
      NEXTJS: 0.95,      // Modern serverless/edge boundaries
      VANILLA_NODE: 1.20 // No security wrappers
    };
    stackMultiplier *= frameworkAdjustments[config.framework];

    // 2C. Environment Exposure Multipliers
    const exposureWeights: Record<EnvironmentExposure, { multiplier: number; label: string }> = {
      PUBLIC_INTERNET: { multiplier: 1.85, label: 'Internet Pública (Borda/Edge)' },
      INTERNAL_VPC: { multiplier: 1.15, label: 'VPC Corporativa / Intranet' },
      AIR_GAPPED: { multiplier: 0.65, label: 'Air-Gapped / Dev Local' }
    };

    const sensitivityWeights: Record<DataSensitivity, { multiplier: number; label: string }> = {
      HIGH_REGULATED: { multiplier: 1.35, label: 'Crítico (PII, PCI-DSS, JWT, DB)' },
      BUSINESS_CONFIDENTIAL: { multiplier: 1.10, label: 'Confidencial de Negócio' },
      PUBLIC_TELEMETRY: { multiplier: 0.85, label: 'Público / Não Sensível' }
    };

    const ingressWeights: Record<IngressProtection, { multiplier: number; label: string; mitigationDesc: string }> = {
      NONE_DIRECT: { multiplier: 1.20, label: 'Acesso Direto (Sem WAF)', mitigationDesc: 'Nenhuma mitigação perimetral ativa' },
      WAF_RATE_LIMIT: { multiplier: 0.80, label: 'WAF Ativo + Rate Limiting', mitigationDesc: 'Mitigação perimetral ativa (-20%)' },
      ZERO_TRUST_MTLS: { multiplier: 0.65, label: 'Zero Trust + mTLS Gateway', mitigationDesc: 'Defesa em profundidade de borda (-35%)' }
    };

    const authWeights: Record<AuthRequirement, { multiplier: number; label: string; mitigationDesc: string }> = {
      ANONYMOUS_PUBLIC: { multiplier: 1.30, label: 'Acesso Anônimo Aberto', mitigationDesc: 'Rotas acessíveis sem credenciais' },
      JWT_SESSION_AUTH: { multiplier: 1.00, label: 'Autenticado (JWT / Session)', mitigationDesc: 'Requer token válido' },
      MFA_RBAC_STRICT: { multiplier: 0.75, label: 'MFA + RBAC Estrito', mitigationDesc: 'Controle de privilégios mínimo (-25%)' }
    };

    const exposureFactor = exposureWeights[config.exposure].multiplier *
      sensitivityWeights[config.dataSensitivity].multiplier *
      ingressWeights[config.ingress].multiplier *
      authWeights[config.auth].multiplier;

    // 2D. Technology Hardening Mitigations (Discount Factors)
    let hardeningFactor = 1.0;
    if (config.tsStrict) hardeningFactor *= 0.85; // -15% for TS strict type-safety
    if (config.helmetEnabled) hardeningFactor *= 0.90; // -10% for HTTP security headers
    if (config.inputValidationEnabled) hardeningFactor *= 0.85; // -15% for runtime validation schemas (Zod/Joi)

    // Node Version Impact
    if (config.nodeVersion === 'NODE_20_22_LTS') hardeningFactor *= 0.95; // Active LTS with latest V8 fixes
    else if (config.nodeVersion === 'NODE_18_LTS') hardeningFactor *= 1.00;
    else if (config.nodeVersion === 'NODE_LEGACY_EOL') hardeningFactor *= 1.35; // EOL Node with known unpatched runtime CVEs

    // 2E. Final Contextual Threat Score (0 - 100)
    let computedThreatScore = 0;
    if (stackFindingStats.totalCount > 0) {
      computedThreatScore = Math.min(100, Math.max(1, Math.round(
        baseFindingLoad * stackMultiplier * exposureFactor * hardeningFactor * 0.45
      )));
    } else {
      // If 0 findings, minimal residual exposure risk based on environment
      computedThreatScore = config.exposure === 'PUBLIC_INTERNET' ? 8 : 2;
    }

    // Determine Threat Level Category
    let threatLevel: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'SECURE' = 'SECURE';
    let threatColor = '#00FF41';
    let threatBadgeBg = 'bg-[#00FF41]/10 text-[#00FF41] border-[#00FF41]/30';
    let threatDescription = 'Postura de segurança controlada com baixo risco de exploração no contexto atual.';

    if (computedThreatScore >= 80) {
      threatLevel = 'CRITICAL';
      threatColor = '#FF3E00';
      threatBadgeBg = 'bg-[#FF3E00]/15 text-[#FF3E00] border-[#FF3E00]/50 shadow-[0_0_15px_rgba(255,62,0,0.4)]';
      threatDescription = 'AMEAÇA CRÍTICA IMINENTE: A combinação de falhas de alto impacto em Node/TS com exposição pública ou dados confidenciais cria alto risco de comprometimento do servidor ou vazamento de credenciais.';
    } else if (computedThreatScore >= 60) {
      threatLevel = 'HIGH';
      threatColor = '#FF7A00';
      threatBadgeBg = 'bg-[#FF7A00]/15 text-[#FF7A00] border-[#FF7A00]/50';
      threatDescription = 'RISCO ELEVADO: Falhas importantes combinadas com superfície de ataque considerável. Ações corretivas devem ser priorizadas no próximo sprint.';
    } else if (computedThreatScore >= 40) {
      threatLevel = 'MODERATE';
      threatColor = '#EAB308';
      threatBadgeBg = 'bg-[#EAB308]/15 text-[#EAB308] border-[#EAB308]/50';
      threatDescription = 'EXPOSIÇÃO MODERADA: Ameaças existentes mitigadas parcialmente pela rede interna ou controles de autenticação. Recomenda-se endurecimento do código.';
    } else if (computedThreatScore >= 20) {
      threatLevel = 'LOW';
      threatColor = '#3366FF';
      threatBadgeBg = 'bg-[#3366FF]/15 text-[#3366FF] border-[#3366FF]/50';
      threatDescription = 'RISCO CONTROLADO: Postura resiliente com controles de isolamento adequados. Mantenha as práticas de varredura contínua.';
    }

    // Simulations: calculate potential score reductions
    const simWithInternalVpc = Math.min(100, Math.max(1, Math.round(
      baseFindingLoad * stackMultiplier * (exposureFactor * (exposureWeights.INTERNAL_VPC.multiplier / exposureWeights[config.exposure].multiplier)) * hardeningFactor * 0.45
    )));
    const vpcReduction = Math.max(0, computedThreatScore - simWithInternalVpc);

    const simWithWaf = Math.min(100, Math.max(1, Math.round(
      baseFindingLoad * stackMultiplier * (exposureFactor * (0.80 / ingressWeights[config.ingress].multiplier)) * hardeningFactor * 0.45
    )));
    const wafReduction = Math.max(0, computedThreatScore - simWithWaf);

    const simWithTsStrict = Math.min(100, Math.max(1, Math.round(
      baseFindingLoad * stackMultiplier * exposureFactor * (hardeningFactor * (config.tsStrict ? 1.0 : 0.85)) * 0.45
    )));
    const tsStrictReduction = config.tsStrict ? 0 : Math.max(0, computedThreatScore - simWithTsStrict);

    const simWithZeroFindings = config.exposure === 'PUBLIC_INTERNET' ? 8 : 2;
    const remediateAllReduction = Math.max(0, computedThreatScore - simWithZeroFindings);

    return {
      baseFindingLoad,
      stackMultiplier: parseFloat(stackMultiplier.toFixed(2)),
      exposureFactor: parseFloat(exposureFactor.toFixed(2)),
      hardeningFactor: parseFloat(hardeningFactor.toFixed(2)),
      computedThreatScore,
      threatLevel,
      threatColor,
      threatBadgeBg,
      threatDescription,
      exposureLabel: exposureWeights[config.exposure].label,
      sensitivityLabel: sensitivityWeights[config.dataSensitivity].label,
      ingressLabel: ingressWeights[config.ingress].label,
      authLabel: authWeights[config.auth].label,
      simulations: {
        vpcReduction,
        wafReduction,
        tsStrictReduction,
        remediateAllReduction
      }
    };
  }, [findings, stackFindingStats, config]);

  const handleCopySummary = () => {
    const summary = [
      `=== SECSCAN SECURITY RISK CALCULATOR ASSESSMENT ===`,
      `Contextual Threat Score: ${calculation.computedThreatScore} / 100 [${calculation.threatLevel}]`,
      `Timestamp: ${new Date().toISOString()}`,
      ``,
      `[1] Technology Stack Context:`,
      `- Runtime: Node.js (Version Tier: ${config.nodeVersion})`,
      `- Framework: ${config.framework}`,
      `- TypeScript Strict: ${config.tsStrict ? 'Enabled (strict: true)' : 'Disabled'}`,
      `- Helmet HTTP Headers: ${config.helmetEnabled ? 'Active' : 'Missing'}`,
      `- Schema Input Validation: ${config.inputValidationEnabled ? 'Active (Zod/Joi)' : 'Missing'}`,
      ``,
      `[2] Environment Exposure:`,
      `- Perimeter: ${calculation.exposureLabel}`,
      `- Data Classification: ${calculation.sensitivityLabel}`,
      `- Ingress Defense: ${calculation.ingressLabel}`,
      `- Authentication: ${calculation.authLabel}`,
      ``,
      `[3] Findings Vector:`,
      `- Total Findings: ${stackFindingStats.totalCount}`,
      `- Critical: ${stackFindingStats.criticalCount} | High: ${stackFindingStats.highCount} | Med: ${stackFindingStats.mediumCount} | Low: ${stackFindingStats.lowCount}`,
      `- Node RCE / Command Exec: ${stackFindingStats.nodeRceCount}`,
      `- Prototype Pollution: ${stackFindingStats.protoPollutionCount}`,
      `- V8 ReDoS Vectors: ${stackFindingStats.reDosCount}`,
      `- Path Traversal: ${stackFindingStats.pathTraversalCount}`,
      `- Leaked Secrets / Keys: ${stackFindingStats.secretsCount}`,
      ``,
      `[4] Multipliers Breakdown:`,
      `- Base Finding Load: ${calculation.baseFindingLoad} pts`,
      `- Stack Threat Factor: ${calculation.stackMultiplier}x`,
      `- Exposure Vector: ${calculation.exposureFactor}x`,
      `- Hardening Factor: ${calculation.hardeningFactor}x`,
      ``,
      `Verdict: ${calculation.threatDescription}`
    ].join('\n');

    navigator.clipboard.writeText(summary);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2500);
  };

  const handleResetDefaults = () => {
    setConfig(DEFAULT_CALCULATOR_CONFIG);
  };

  return (
    <div id="security-risk-calculator-section" className="bg-[#0A0A0A] border border-[#222] p-6 sm:p-8 space-y-6 relative overflow-hidden font-mono">
      {/* Background cyber accent glow */}
      <div 
        className="absolute top-0 right-0 w-96 h-96 rounded-full pointer-events-none blur-3xl opacity-10"
        style={{ backgroundColor: calculation.threatColor }}
      />

      {/* Header Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-[#222]">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-black tracking-[0.25em] text-[#FF3E00] uppercase">
              // THREAT ENGINE
            </span>
            <span className="px-2 py-0.5 text-[9px] font-bold bg-[#1C1C1C] text-[#AAA] border border-[#333] uppercase">
              NODE/TS &bull; V8 RUNTIME
            </span>
            <span className="px-2 py-0.5 text-[9px] font-bold bg-[#1C1C1C] text-[#AAA] border border-[#333] uppercase">
              CONTEXTUAL RISK
            </span>
          </div>
          <h3 className="text-xl sm:text-2xl font-black text-white uppercase tracking-tight flex items-center gap-2.5">
            <Cpu className="w-6 h-6 text-[#FF3E00]" />
            <span>Security Risk Calculator</span>
          </h3>
          <p className="text-xs text-[#888] max-w-2xl">
            Calcula o <strong className="text-white">Score de Ameaça Contextual</strong> combinando a stack tecnológica (<span className="text-[#00FF41]">Node.js &amp; TypeScript</span>), a exposição ambiental do serviço (<span className="text-[#FF7A00]">Público vs. VPC Interna</span>) e as vulnerabilidades ativas.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={handleCopySummary}
            className="px-3.5 py-2 bg-[#141414] hover:bg-[#202020] border border-[#333] hover:border-white text-xs text-[#DDD] font-bold uppercase transition-all flex items-center gap-1.5 cursor-pointer"
            title="Copiar relatório contextual detalhado para a área de transferência"
          >
            {copiedSummary ? <Check className="w-3.5 h-3.5 text-[#00FF41]" /> : <Copy className="w-3.5 h-3.5 text-[#AAA]" />}
            <span>{copiedSummary ? 'Copiado!' : 'Copiar Relatório'}</span>
          </button>

          <button
            type="button"
            onClick={handleResetDefaults}
            className="px-3 py-2 bg-[#141414] hover:bg-[#202020] border border-[#333] hover:border-white text-xs text-[#888] hover:text-white font-bold uppercase transition-all flex items-center gap-1.5 cursor-pointer"
            title="Restaurar parâmetros padrão da calculadora"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Redefinir</span>
          </button>
        </div>
      </div>

      {/* Main Score Hero and Key Multipliers Display */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* Left Column: Contextual Threat Score Gauge & Verdict */}
        <div className="lg:col-span-5 bg-[#070707] border border-[#222] p-6 flex flex-col justify-between relative overflow-hidden group">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-bold tracking-wider text-[#888] uppercase">
              Score de Ameaça Contextual
            </span>
            <span className={`px-2.5 py-0.5 text-[10px] font-black uppercase border ${calculation.threatBadgeBg}`}>
              {calculation.threatLevel}
            </span>
          </div>

          {/* Large Visual Score Display */}
          <div className="my-6 text-center">
            <div className="relative inline-flex flex-col items-center justify-center">
              {/* Semi-circular radial gauge background */}
              <svg className="w-48 h-28 overflow-visible" viewBox="0 0 160 90">
                <path
                  d="M 15 85 A 65 65 0 0 1 145 85"
                  fill="none"
                  stroke="#1A1A1A"
                  strokeWidth="14"
                  strokeLinecap="round"
                />
                <path
                  d="M 15 85 A 65 65 0 0 1 145 85"
                  fill="none"
                  stroke={calculation.threatColor}
                  strokeWidth="14"
                  strokeLinecap="round"
                  strokeDasharray="204"
                  strokeDashoffset={204 - (204 * (calculation.computedThreatScore / 100))}
                  className="transition-all duration-700 ease-out"
                />
              </svg>

              {/* Central Numeric Score */}
              <div className="absolute top-10 flex flex-col items-center">
                <span 
                  className="text-5xl sm:text-6xl font-black tracking-tight"
                  style={{ color: calculation.threatColor }}
                >
                  {calculation.computedThreatScore}
                </span>
                <span className="text-[10px] text-[#777] uppercase font-bold tracking-widest -mt-1">
                  / 100 PONTOS
                </span>
              </div>
            </div>

            <p className="text-xs text-[#CCC] mt-2 px-3 leading-relaxed">
              {calculation.threatDescription}
            </p>
          </div>

          {/* Quick Context Summary Pills */}
          <div className="pt-4 border-t border-[#181818] grid grid-cols-2 gap-2 text-[10px]">
            <div className="bg-[#101010] p-2 border border-[#222]">
              <span className="text-[#666] block">Perímetro:</span>
              <strong className="text-white truncate block">{calculation.exposureLabel}</strong>
            </div>
            <div className="bg-[#101010] p-2 border border-[#222]">
              <span className="text-[#666] block">Stack Runtime:</span>
              <strong className="text-[#00FF41] block">Node.js ({config.framework})</strong>
            </div>
          </div>
        </div>

        {/* Right Column: 4 Scientific Multiplier Breakdowns */}
        <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Factor 1: Base Finding Load */}
          <div className="bg-[#070707] border border-[#222] p-5 flex flex-col justify-between hover:border-[#333] transition-colors">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-[#888] uppercase">1. Carga Base dos Achados</span>
              <Flame className="w-4 h-4 text-[#FF3E00]" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-black text-white">{calculation.baseFindingLoad} <span className="text-xs text-[#777] font-normal">pts</span></div>
              <div className="text-[11px] text-[#888] mt-1">
                {stackFindingStats.totalCount} achados detectados ({stackFindingStats.criticalCount}C, {stackFindingStats.highCount}H, {stackFindingStats.mediumCount}M)
              </div>
            </div>
            <div className="text-[10px] text-[#666] pt-2 border-t border-[#181818] flex justify-between">
              <span>Críticos: {stackFindingStats.criticalCount}</span>
              <span>Altos: {stackFindingStats.highCount}</span>
              <span>Médios: {stackFindingStats.mediumCount}</span>
            </div>
          </div>

          {/* Factor 2: Node/TS Stack Vulnerability Factor */}
          <div className="bg-[#070707] border border-[#222] p-5 flex flex-col justify-between hover:border-[#333] transition-colors">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-[#888] uppercase">2. Fator Stack Node/TS</span>
              <Layers className="w-4 h-4 text-[#00FF41]" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-black text-[#00FF41]">
                {calculation.stackMultiplier}x
              </div>
              <div className="text-[11px] text-[#888] mt-1">
                {stackFindingStats.nodeRceCount > 0 ? (
                  <span className="text-[#FF3E00] font-bold">{stackFindingStats.nodeRceCount} RCE / Command Exec detectado!</span>
                ) : stackFindingStats.protoPollutionCount > 0 ? (
                  <span className="text-[#FF7A00] font-bold">Prototype Pollution no Node detectado!</span>
                ) : (
                  <span>Vulnerabilidades específicas do ecossistema JS/V8</span>
                )}
              </div>
            </div>
            <div className="text-[10px] text-[#666] pt-2 border-t border-[#181818] flex justify-between">
              <span>ReDoS: {stackFindingStats.reDosCount}</span>
              <span>Proto: {stackFindingStats.protoPollutionCount}</span>
              <span>Secrets: {stackFindingStats.secretsCount}</span>
            </div>
          </div>

          {/* Factor 3: Environment Exposure Vector */}
          <div className="bg-[#070707] border border-[#222] p-5 flex flex-col justify-between hover:border-[#333] transition-colors">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-[#888] uppercase">3. Vetor de Exposição</span>
              <Globe className="w-4 h-4 text-[#FF7A00]" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-black text-[#FF7A00]">
                {calculation.exposureFactor}x
              </div>
              <div className="text-[11px] text-[#888] mt-1 truncate" title={calculation.exposureLabel}>
                {config.exposure === 'PUBLIC_INTERNET' ? 'Acesso Aberto pela Internet' : 'Restrito em Rede Privada'}
              </div>
            </div>
            <div className="text-[10px] text-[#666] pt-2 border-t border-[#181818] flex justify-between">
              <span>Perímetro: {config.exposure}</span>
              <span>WAF: {config.ingress !== 'NONE_DIRECT' ? 'SIM' : 'NÃO'}</span>
            </div>
          </div>

          {/* Factor 4: Hardening & Mitigations */}
          <div className="bg-[#070707] border border-[#222] p-5 flex flex-col justify-between hover:border-[#333] transition-colors">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-[#888] uppercase">4. Mitigações &amp; Hardening</span>
              <ShieldCheck className="w-4 h-4 text-[#3366FF]" />
            </div>
            <div className="my-2">
              <div className="text-3xl font-black text-[#3366FF]">
                {calculation.hardeningFactor}x
              </div>
              <div className="text-[11px] text-[#888] mt-1">
                {config.tsStrict ? 'TS Strict ativado (-15%)' : 'Sem TS Strict (risco de coação)'}
              </div>
            </div>
            <div className="text-[10px] text-[#666] pt-2 border-t border-[#181818] flex justify-between">
              <span>Helmet: {config.helmetEnabled ? 'ATIVO' : 'DESAT'}</span>
              <span>Zod/Joi: {config.inputValidationEnabled ? 'ATIVO' : 'DESAT'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs for Interactive Calculator */}
      <div className="flex items-center gap-2 border-b border-[#222] pt-2">
        <button
          type="button"
          onClick={() => setActiveTab('OVERVIEW')}
          className={`px-4 py-2 text-xs font-bold uppercase transition-all border-b-2 cursor-pointer ${
            activeTab === 'OVERVIEW'
              ? 'text-white border-[#FF3E00] bg-[#141414]'
              : 'text-[#888] border-transparent hover:text-white hover:bg-[#111]'
          }`}
        >
          <span className="flex items-center gap-1.5">
            <Sliders className="w-3.5 h-3.5 text-[#FF3E00]" />
            <span>Parâmetros &amp; Exposição</span>
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('SIMULATOR')}
          className={`px-4 py-2 text-xs font-bold uppercase transition-all border-b-2 cursor-pointer ${
            activeTab === 'SIMULATOR'
              ? 'text-white border-[#FF3E00] bg-[#141414]'
              : 'text-[#888] border-transparent hover:text-white hover:bg-[#111]'
          }`}
        >
          <span className="flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#00FF41]" />
            <span>Simulador What-If</span>
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('HARDENING')}
          className={`px-4 py-2 text-xs font-bold uppercase transition-all border-b-2 cursor-pointer ${
            activeTab === 'HARDENING'
              ? 'text-white border-[#FF3E00] bg-[#141414]'
              : 'text-[#888] border-transparent hover:text-white hover:bg-[#111]'
          }`}
        >
          <span className="flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-[#3366FF]" />
            <span>Hardening Node/TS</span>
          </span>
        </button>
      </div>

      {/* TAB 1: INTERACTIVE PARAMETERS & ENVIRONMENT CONFIGURATION */}
      {activeTab === 'OVERVIEW' && (
        <div className="space-y-6 animate-fadeIn">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Control 1: Environment Exposure */}
            <div className="bg-[#070707] border border-[#222] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-[#FF7A00]" />
                  <span>Exposição do Perímetro</span>
                </label>
                <span className="text-[10px] text-[#777]">Attack Surface</span>
              </div>
              <div className="space-y-2">
                {[
                  { id: 'PUBLIC_INTERNET', label: 'Internet Pública (Edge / Borda)', desc: 'Qualquer atacante externo pode sondar rotas', weight: '1.85x' },
                  { id: 'INTERNAL_VPC', label: 'VPC Corporativa / Intranet', desc: 'Requer VPN ou acesso lateral corporativo', weight: '1.15x' },
                  { id: 'AIR_GAPPED', label: 'Air-Gapped / Dev Local', desc: 'Isolado da internet sem conectividade direta', weight: '0.65x' },
                ].map((opt) => (
                  <div
                    key={opt.id}
                    onClick={() => setConfig({ ...config, exposure: opt.id as EnvironmentExposure })}
                    className={`p-3 border transition-all cursor-pointer ${
                      config.exposure === opt.id
                        ? 'border-[#FF3E00] bg-[#FF3E00]/10 text-white'
                        : 'border-[#1E1E1E] bg-[#0E0E0E] text-[#888] hover:border-[#333]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-bold">
                      <span className={config.exposure === opt.id ? 'text-white' : 'text-[#AAA]'}>{opt.label}</span>
                      <span className="text-[10px] font-mono text-[#FF7A00]">{opt.weight}</span>
                    </div>
                    <div className="text-[10px] text-[#666] mt-0.5">{opt.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Control 2: Data Sensitivity */}
            <div className="bg-[#070707] border border-[#222] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-[#FF3E00]" />
                  <span>Sensibilidade dos Dados</span>
                </label>
                <span className="text-[10px] text-[#777]">Impact Vector</span>
              </div>
              <div className="space-y-2">
                {[
                  { id: 'HIGH_REGULATED', label: 'PII, Cartões, JWT, DB Secrets', desc: 'Alto risco regulatório (LGPD/PCI-DSS/HIPAA)', weight: '1.35x' },
                  { id: 'BUSINESS_CONFIDENTIAL', label: 'Confidencial / Negócio', desc: 'Regras de negócio e sessões privadas', weight: '1.10x' },
                  { id: 'PUBLIC_TELEMETRY', label: 'Dados Públicos / Catálogo', desc: 'Informações abertas e não sensíveis', weight: '0.85x' },
                ].map((opt) => (
                  <div
                    key={opt.id}
                    onClick={() => setConfig({ ...config, dataSensitivity: opt.id as DataSensitivity })}
                    className={`p-3 border transition-all cursor-pointer ${
                      config.dataSensitivity === opt.id
                        ? 'border-[#FF3E00] bg-[#FF3E00]/10 text-white'
                        : 'border-[#1E1E1E] bg-[#0E0E0E] text-[#888] hover:border-[#333]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-bold">
                      <span className={config.dataSensitivity === opt.id ? 'text-white' : 'text-[#AAA]'}>{opt.label}</span>
                      <span className="text-[10px] font-mono text-[#FF3E00]">{opt.weight}</span>
                    </div>
                    <div className="text-[10px] text-[#666] mt-0.5">{opt.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Control 3: Ingress Protection */}
            <div className="bg-[#070707] border border-[#222] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-[#3366FF]" />
                  <span>Defesa de Borda (Ingress)</span>
                </label>
                <span className="text-[10px] text-[#777]">Perimeter Defense</span>
              </div>
              <div className="space-y-2">
                {[
                  { id: 'NONE_DIRECT', label: 'Acesso Direto Sem WAF', desc: 'Sem filtro de payloads maliciosos na borda', weight: '1.20x' },
                  { id: 'WAF_RATE_LIMIT', label: 'WAF Ativo + Rate Limiting', desc: 'Bloqueio de injeções conhecidas (-20%)', weight: '0.80x' },
                  { id: 'ZERO_TRUST_MTLS', label: 'Zero Trust + mTLS Gateway', desc: 'Autenticação mútua forte de borda (-35%)', weight: '0.65x' },
                ].map((opt) => (
                  <div
                    key={opt.id}
                    onClick={() => setConfig({ ...config, ingress: opt.id as IngressProtection })}
                    className={`p-3 border transition-all cursor-pointer ${
                      config.ingress === opt.id
                        ? 'border-[#3366FF] bg-[#3366FF]/10 text-white'
                        : 'border-[#1E1E1E] bg-[#0E0E0E] text-[#888] hover:border-[#333]'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-bold">
                      <span className={config.ingress === opt.id ? 'text-white' : 'text-[#AAA]'}>{opt.label}</span>
                      <span className="text-[10px] font-mono text-[#3366FF]">{opt.weight}</span>
                    </div>
                    <div className="text-[10px] text-[#666] mt-0.5">{opt.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Control 4: Node.js Framework */}
            <div className="bg-[#070707] border border-[#222] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-[#00FF41]" />
                  <span>Framework Node.js</span>
                </label>
                <span className="text-[10px] text-[#777]">Architecture</span>
              </div>
              <select
                value={config.framework}
                onChange={(e) => setConfig({ ...config, framework: e.target.value as NodeFramework })}
                className="w-full bg-[#111] border border-[#333] text-white text-xs p-2.5 font-mono focus:border-[#FF3E00] focus:outline-none cursor-pointer"
              >
                <option value="EXPRESS">Express.js (Padrão minimalista - 1.05x)</option>
                <option value="NESTJS">NestJS (Enterprise com ValidationPipes - 0.90x)</option>
                <option value="FASTIFY">Fastify (Schema validation nativo - 0.95x)</option>
                <option value="NEXTJS">Next.js (Edge &amp; Server Actions - 0.95x)</option>
                <option value="VANILLA_NODE">Node HTTP Puro (Sem wrappers - 1.20x)</option>
              </select>
              <div className="text-[11px] text-[#777]">
                Frameworks com validação de esquema estrita (Fastify/NestJS) oferecem maior proteção contra injeções e coerção de tipos.
              </div>
            </div>

            {/* Control 5: Node.js Version Tier */}
            <div className="bg-[#070707] border border-[#222] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-[#00FF41]" />
                  <span>Versão do Runtime Node.js</span>
                </label>
                <span className="text-[10px] text-[#777]">V8 Engine</span>
              </div>
              <select
                value={config.nodeVersion}
                onChange={(e) => setConfig({ ...config, nodeVersion: e.target.value as NodeVersionTier })}
                className="w-full bg-[#111] border border-[#333] text-white text-xs p-2.5 font-mono focus:border-[#FF3E00] focus:outline-none cursor-pointer"
              >
                <option value="NODE_20_22_LTS">Node.js 20 / 22 LTS (Active LTS, Permission Model - 0.95x)</option>
                <option value="NODE_18_LTS">Node.js 18 LTS (Maintenance - 1.00x)</option>
                <option value="NODE_LEGACY_EOL">Node.js &lt;= 16 EOL (Vulnerável a CVEs de OpenSSL/V8 - 1.35x)</option>
              </select>
              <div className="text-[11px] text-[#777]">
                Versões antigas de Node.js possuem vulnerabilidades conhecidas no motor V8 e biblioteca OpenSSL.
              </div>
            </div>

            {/* Control 6: Node & TypeScript Toggles */}
            <div className="bg-[#070707] border border-[#222] p-5 space-y-3 flex flex-col justify-between">
              <label className="text-xs font-bold text-white uppercase flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-[#3366FF]" />
                <span>Controles de Hardening em Código</span>
              </label>
              <div className="space-y-2.5">
                <label className="flex items-center justify-between p-2 bg-[#111] border border-[#222] cursor-pointer hover:border-[#333]">
                  <span className="text-xs text-white">TypeScript Strict Mode (`strict: true`)</span>
                  <input
                    type="checkbox"
                    checked={config.tsStrict}
                    onChange={(e) => setConfig({ ...config, tsStrict: e.target.checked })}
                    className="accent-[#FF3E00] w-4 h-4 cursor-pointer"
                  />
                </label>
                <label className="flex items-center justify-between p-2 bg-[#111] border border-[#222] cursor-pointer hover:border-[#333]">
                  <span className="text-xs text-white">Helmet.js (Secure HTTP Headers)</span>
                  <input
                    type="checkbox"
                    checked={config.helmetEnabled}
                    onChange={(e) => setConfig({ ...config, helmetEnabled: e.target.checked })}
                    className="accent-[#FF3E00] w-4 h-4 cursor-pointer"
                  />
                </label>
                <label className="flex items-center justify-between p-2 bg-[#111] border border-[#222] cursor-pointer hover:border-[#333]">
                  <span className="text-xs text-white">Validação de Entrada Zod / Joi</span>
                  <input
                    type="checkbox"
                    checked={config.inputValidationEnabled}
                    onChange={(e) => setConfig({ ...config, inputValidationEnabled: e.target.checked })}
                    className="accent-[#FF3E00] w-4 h-4 cursor-pointer"
                  />
                </label>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: WHAT-IF SCENARIO SIMULATOR */}
      {activeTab === 'SIMULATOR' && (
        <div className="space-y-4 animate-fadeIn">
          <div className="p-4 bg-[#070707] border border-[#222] space-y-1">
            <h4 className="text-sm font-black text-white uppercase flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#00FF41]" />
              <span>Simulador de Impacto e Redução de Ameaças</span>
            </h4>
            <p className="text-xs text-[#888]">
              Veja como intervenções arquiteturais e de código reduzem imediatamente o score de risco contextual da aplicação.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Simulation Card 1: Isolamento de Rede */}
            <div className="p-5 bg-[#070707] border border-[#222] hover:border-[#FF7A00] transition-all space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-[#888] uppercase">Migrar para VPC Privada</span>
                <Globe className="w-4 h-4 text-[#FF7A00]" />
              </div>
              <div>
                <div className="text-3xl font-black text-[#FF7A00]">
                  -{calculation.simulations.vpcReduction} <span className="text-xs font-normal text-[#888]">pontos</span>
                </div>
                <div className="text-xs text-[#CCC] mt-1">
                  Retira o serviço da internet pública, exigindo autenticação corporativa/VPN prévia.
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConfig({ ...config, exposure: 'INTERNAL_VPC' })}
                disabled={config.exposure === 'INTERNAL_VPC'}
                className="w-full py-2 bg-[#1A1A1A] hover:bg-[#FF7A00] hover:text-black text-white text-xs font-bold uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                {config.exposure === 'INTERNAL_VPC' ? 'Cenário Ativo' : 'Aplicar Simulação'}
              </button>
            </div>

            {/* Simulation Card 2: Ativação de WAF */}
            <div className="p-5 bg-[#070707] border border-[#222] hover:border-[#3366FF] transition-all space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-[#888] uppercase">Ativar WAF + Rate Limit</span>
                <Lock className="w-4 h-4 text-[#3366FF]" />
              </div>
              <div>
                <div className="text-3xl font-black text-[#3366FF]">
                  -{calculation.simulations.wafReduction} <span className="text-xs font-normal text-[#888]">pontos</span>
                </div>
                <div className="text-xs text-[#CCC] mt-1">
                  Filtra injeções de SQL, command injection e força bruta na camada de borda Cloudflare/AWS.
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConfig({ ...config, ingress: 'WAF_RATE_LIMIT' })}
                disabled={config.ingress === 'WAF_RATE_LIMIT'}
                className="w-full py-2 bg-[#1A1A1A] hover:bg-[#3366FF] hover:text-white text-white text-xs font-bold uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                {config.ingress === 'WAF_RATE_LIMIT' ? 'Cenário Ativo' : 'Aplicar Simulação'}
              </button>
            </div>

            {/* Simulation Card 3: Ativar TS Strict */}
            <div className="p-5 bg-[#070707] border border-[#222] hover:border-[#00FF41] transition-all space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-[#888] uppercase">Ativar TypeScript Strict</span>
                <Terminal className="w-4 h-4 text-[#00FF41]" />
              </div>
              <div>
                <div className="text-3xl font-black text-[#00FF41]">
                  -{calculation.simulations.tsStrictReduction} <span className="text-xs font-normal text-[#888]">pontos</span>
                </div>
                <div className="text-xs text-[#CCC] mt-1">
                  Habilita `noImplicitAny` e checagem rígida de tipos prevenindo poluição de protótipo passiva.
                </div>
              </div>
              <button
                type="button"
                onClick={() => setConfig({ ...config, tsStrict: true })}
                disabled={config.tsStrict}
                className="w-full py-2 bg-[#1A1A1A] hover:bg-[#00FF41] hover:text-black text-white text-xs font-bold uppercase transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              >
                {config.tsStrict ? 'Cenário Ativo' : 'Aplicar Simulação'}
              </button>
            </div>

            {/* Simulation Card 4: Remediar Todos os Achados */}
            <div className="p-5 bg-[#070707] border border-[#222] hover:border-[#FF3E00] transition-all space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold text-[#888] uppercase">Remediar Todos os Achados</span>
                <CheckCircle2 className="w-4 h-4 text-[#FF3E00]" />
              </div>
              <div>
                <div className="text-3xl font-black text-[#FF3E00]">
                  -{calculation.simulations.remediateAllReduction} <span className="text-xs font-normal text-[#888]">pontos</span>
                </div>
                <div className="text-xs text-[#CCC] mt-1">
                  Resolve todas as {stackFindingStats.totalCount} vulnerabilidades do SAST, atingindo postura nominal.
                </div>
              </div>
              <button
                type="button"
                onClick={onNavigateToScanner}
                className="w-full py-2 bg-[#FF3E00] hover:bg-white hover:text-black text-white text-xs font-bold uppercase transition-all cursor-pointer flex items-center justify-center gap-1"
              >
                <span>Ir para o Scanner</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: NODE/TS HARDENING GUIDELINES */}
      {activeTab === 'HARDENING' && (
        <div className="space-y-4 animate-fadeIn">
          <div className="p-4 bg-[#070707] border border-[#222] space-y-1">
            <h4 className="text-sm font-black text-white uppercase flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#3366FF]" />
              <span>Guias Práticos de Hardening para Node.js &amp; TypeScript</span>
            </h4>
            <p className="text-xs text-[#888]">
              Práticas recomendadas para mitigar os vetores de ataque mais críticos do ecossistema JavaScript / V8.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* Guide 1: Prototype Pollution Protection */}
            <div className="p-4 bg-[#050505] border border-[#222] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white uppercase">1. Prevenção de Prototype Pollution</span>
                <span className="text-[10px] text-[#FF3E00] font-bold">CWE-1321</span>
              </div>
              <p className="text-[#888] leading-relaxed">
                No Node.js, poluir `Object.prototype` afeta todos os objetos da aplicação, podendo levar a DoS ou RCE.
              </p>
              <div className="p-2.5 bg-[#000] border border-[#1C1C1C] text-[#00FF41] text-[11px] font-mono overflow-x-auto">
                <code>{`// Bloquear poluição no início do processo:\nObject.freeze(Object.prototype);\n// Ou iniciar o Node com a flag:\nnode --disable-proto=delete app.js`}</code>
              </div>
            </div>

            {/* Guide 2: Safe Child Process Execution */}
            <div className="p-4 bg-[#050505] border border-[#222] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white uppercase">2. Execução Segura de Comandos OS</span>
                <span className="text-[10px] text-[#FF3E00] font-bold">CWE-78</span>
              </div>
              <p className="text-[#888] leading-relaxed">
                Nunca use `child_process.exec()` com concatenação de strings de entrada do usuário. Use `execFile` com argumentos em array.
              </p>
              <div className="p-2.5 bg-[#000] border border-[#1C1C1C] text-[#00FF41] text-[11px] font-mono overflow-x-auto">
                <code>{`// Inseguro: exec('git ' + userBranch)\n// Seguro:\nimport { execFile } from 'child_process';\nexecFile('git', ['checkout', userBranch], callback);`}</code>
              </div>
            </div>

            {/* Guide 3: ReDoS Mitigation in V8 */}
            <div className="p-4 bg-[#050505] border border-[#222] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white uppercase">3. Mitigação de ReDoS no Event Loop</span>
                <span className="text-[10px] text-[#EAB308] font-bold">CWE-1333</span>
              </div>
              <p className="text-[#888] leading-relaxed">
                Expressões regulares com backtracking catastrófico congelam a thread única do Node.js, derrubando a API.
              </p>
              <div className="p-2.5 bg-[#000] border border-[#1C1C1C] text-[#00FF41] text-[11px] font-mono overflow-x-auto">
                <code>{`// Use o módulo seguro re2 ou timeouts regex:\nimport RE2 from 're2';\nconst safePattern = new RE2(/^[a-zA-Z0-9]+$/);`}</code>
              </div>
            </div>

            {/* Guide 4: Helmet.js Security Headers */}
            <div className="p-4 bg-[#050505] border border-[#222] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-white uppercase">4. Headers de Segurança HTTP (Helmet)</span>
                <span className="text-[10px] text-[#3366FF] font-bold">OWASP A05</span>
              </div>
              <p className="text-[#888] leading-relaxed">
                Adiciona Content-Security-Policy, HSTS, X-Content-Type-Options e bloqueia detecção do Express (`x-powered-by`).
              </p>
              <div className="p-2.5 bg-[#000] border border-[#1C1C1C] text-[#00FF41] text-[11px] font-mono overflow-x-auto">
                <code>{`import helmet from 'helmet';\napp.use(helmet({\n  contentSecurityPolicy: true,\n  hidePoweredBy: true\n}));`}</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Action Footer */}
      <div className="pt-4 border-t border-[#222] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-[#888]">
        <div className="flex items-center gap-2">
          <Info className="w-4 h-4 text-[#FF3E00]" />
          <span>
            Os parâmetros da calculadora são persistidos localmente e integrados ao Risk Score do Dashboard.
          </span>
        </div>
        {onNavigateToScanner && (
          <button
            type="button"
            onClick={onNavigateToScanner}
            className="text-white hover:text-[#FF3E00] font-bold uppercase flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <span>Ver Todas as Vulnerabilidades no Scanner</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
};
