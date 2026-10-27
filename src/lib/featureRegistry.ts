export type FeatureCategory = 'CODE_SAST' | 'CLOUD_INFRA' | 'API_DAST' | 'SOC_EDR' | 'GOV_AI';

export interface FeatureRegistryItem {
  id: string;
  name: string;
  category: FeatureCategory;
}

/** Same drawers as the module hub. Analytics on the Express server reads this list. */
export const FEATURE_REGISTRY: FeatureRegistryItem[] = [
  { id: 'scanner', name: 'Scanner SAST & AST', category: 'CODE_SAST' },
  { id: 'dataflow', name: 'Data Flow Taint Graph', category: 'CODE_SAST' },
  { id: 'endpoints', name: 'API Surface & Endpoints', category: 'CODE_SAST' },
  { id: 'entropy', name: 'High-Entropy Secret Detection', category: 'CODE_SAST' },
  { id: 'jsminer', name: 'JS Miner & Secrets', category: 'CODE_SAST' },
  { id: 'sca', name: 'SCA Dependency Audit', category: 'CODE_SAST' },
  { id: 'autoremediation', name: '1-Click Auto Remediation', category: 'CODE_SAST' },
  { id: 'refactoring', name: 'AI Security Refactoring', category: 'CODE_SAST' },

  { id: 'apisecurity', name: 'OWASP API Security Top 10', category: 'API_DAST' },
  { id: 'dast', name: 'DAST Active Dynamic Scan', category: 'API_DAST' },
  { id: 'iast', name: 'IAST Simulated Payloads', category: 'API_DAST' },
  { id: 'headers', name: 'HTTP Security Headers', category: 'API_DAST' },
  { id: 'jwtinspector', name: 'JWT Token Inspector', category: 'API_DAST' },
  { id: 'ssrfvalidator', name: 'SSRF Gateway Validator', category: 'API_DAST' },
  { id: 'waf', name: 'ModSecurity WAF Rules', category: 'API_DAST' },
  { id: 'nmap', name: 'Network Recon & Nmap', category: 'API_DAST' },
  { id: 'nikto', name: 'Nikto Web Server Audit', category: 'API_DAST' },

  { id: 'iac', name: 'IaC Security & Misconfigs', category: 'CLOUD_INFRA' },
  { id: 'containerscan', name: 'Container CIS Benchmark', category: 'CLOUD_INFRA' },
  { id: 'cloudiam', name: 'Cloud IAM Policy Audit', category: 'CLOUD_INFRA' },
  { id: 'ngfw', name: 'Next-Gen Firewall / IPS', category: 'CLOUD_INFRA' },
  { id: 'idsips', name: 'Suricata IDS DPI', category: 'CLOUD_INFRA' },
  { id: 'dnssec', name: 'DNS & DNSSEC', category: 'CLOUD_INFRA' },
  { id: 'sdwan', name: 'SD-WAN & SASE', category: 'CLOUD_INFRA' },

  { id: 'soccommand', name: 'SOC Command Center Live', category: 'SOC_EDR' },
  { id: 'securityonion', name: 'Security Onion Alerts', category: 'SOC_EDR' },
  { id: 'crowdstrike', name: 'CrowdStrike Falcon Sensor', category: 'SOC_EDR' },
  { id: 'edr', name: 'eBPF Endpoint Detection', category: 'SOC_EDR' },

  { id: 'dashboard', name: 'Executive SecOps Dashboard', category: 'GOV_AI' },
  { id: 'trenddashboard', name: 'Risk Trend & MTTR', category: 'GOV_AI' },
  { id: 'ctihub', name: 'CTI Threat Intel & Radar', category: 'GOV_AI' },
  { id: 'threatmodel', name: 'STRIDE Threat Modeling', category: 'GOV_AI' },
  { id: 'policyascode', name: 'OPA Rego Policy Engine', category: 'GOV_AI' },
  { id: 'sbom', name: 'CycloneDX SBOM Generator', category: 'GOV_AI' },
  { id: 'compliance', name: 'SOC2 & ISO27001 Compliance', category: 'GOV_AI' },
  { id: 'frameworks', name: 'NIST CSF & CIS Matrix', category: 'GOV_AI' },
  { id: 'asocsla', name: 'ASOC SLA & MTTR Tracking', category: 'GOV_AI' },
  { id: 'llmsecurity', name: 'OWASP Top 10 for LLMs', category: 'GOV_AI' },
  { id: 'soarbuilder', name: 'SOAR Playbooks', category: 'GOV_AI' },
  { id: 'procyber', name: 'Pro Cyber Utilities', category: 'GOV_AI' },
  { id: 'rules', name: 'SAST Custom Rules Engine', category: 'GOV_AI' },
  { id: 'cli', name: 'Interactive CLI', category: 'GOV_AI' },
  { id: 'pipelineflow', name: 'Pipeline Flow', category: 'GOV_AI' },
  { id: 'cicd', name: 'CI/CD Health', category: 'GOV_AI' },
];
