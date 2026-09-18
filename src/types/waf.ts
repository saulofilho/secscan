export type WafAction = 'BLOCK_403' | 'CHALLENGE_CAPTCHA' | 'LOG_ONLY' | 'RATE_LIMIT' | 'REDIRECT';

export type WafAttackType =
  | 'SQL_INJECTION'
  | 'CROSS_SITE_SCRIPTING'
  | 'REMOTE_CODE_EXECUTION'
  | 'SERVER_SIDE_REQUEST_FORGERY'
  | 'PATH_TRAVERSAL'
  | 'BAD_BOT_SCRAPER'
  | 'CREDENTIAL_STUFFING'
  | 'API_ABUSE';

export interface WafSecurityRule {
  id: string;
  ruleId: number; // Ex: 942100 (OWASP CRS)
  name: string;
  category: WafAttackType;
  anomalyScore: number; // Ex: 5 (adicionado ao threshold)
  action: WafAction;
  phase: 1 | 2; // Phase 1: Request Headers, Phase 2: Request Body
  patternRegex: string;
  enabled: boolean;
  totalHits: number;
  owaspCrsReference: string;
}

export interface WafLiveBlockedEvent {
  id: string;
  timestamp: string;
  clientIp: string;
  clientGeo: string; // Ex: "🇷🇺 São Petersburgo, RU" ou "🇺🇸 Boydton, US"
  httpMethod: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  uriPath: string;
  userAgent: string;
  attackType: WafAttackType;
  triggeredRules: {
    ruleId: number;
    ruleName: string;
    matchedString: string;
    anomalyScore: number;
  }[];
  totalAnomalyScore: number;
  actionEnforced: WafAction;
  httpStatusReturned: number;
  payloadSnippet: string;
  botScore: number; // 0 - 100 (100 = Automação/Bot malicioso)
}

export interface WafRateLimitPolicy {
  id: string;
  name: string;
  targetEndpoint: string;
  rateLimitThreshold: number; // Ex: 100 reqs
  windowSeconds: number; // Ex: 60s
  actionOnExceed: 'CHALLENGE_CAPTCHA' | 'BLOCK_429';
  activeBansCount: number;
  enabled: boolean;
}

export interface WafVirtualPatch {
  cveId: string;
  targetSoftware: string;
  description: string;
  mitigationRuleId: number;
  activeStatus: 'SHIELDED' | 'MONITORING';
  patchDate: string;
}

export interface WafEngineOverview {
  mode: 'BLOCKING_ACTIVE' | 'LEARNING_MODE';
  anomalyThreshold: number; // Ex: 10
  totalRequestsToday: number;
  blockedAttacksToday: number;
  activeVirtualPatchesCount: number;
  botMitigationRate: number; // Ex: 98.6%
  avgInspectionLatencyMs: number; // Ex: 1.2ms
}
