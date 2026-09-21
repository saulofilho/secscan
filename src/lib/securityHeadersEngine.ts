import {
  SecurityHeaderRule,
  HeaderEvaluationResult,
  SecurityHeadersAuditReport,
  HeaderGrade,
  CspDirective
} from '../types/securityTools';

export const STANDARD_SECURITY_HEADER_RULES: SecurityHeaderRule[] = [
  {
    headerName: 'Content-Security-Policy',
    category: 'XSS_CSP',
    importance: 'CRITICAL',
    recommendedValue: "default-src 'self'; script-src 'self' 'nonce-rAnd0m'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
    description: 'Controla rigidamente as origens das quais scripts, estilos, imagens e iframes podem ser carregados.',
    securityImpact: 'Neutraliza Cross-Site Scripting (XSS), ataques de injeção de pacotes e carregamento de código malicioso.',
    cwe: 'CWE-79',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
  },
  {
    headerName: 'Strict-Transport-Security',
    category: 'TRANSPORT',
    importance: 'CRITICAL',
    recommendedValue: 'max-age=31536000; includeSubDomains; preload',
    description: 'Força os navegadores a se comunicarem estritamente via HTTPS encriptado por no mínimo 1 ano.',
    securityImpact: 'Protege contra SSL Stripping, ataques Man-in-the-Middle (MitM) e interceptação em redes Wi-Fi públicas.',
    cwe: 'CWE-319',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
  },
  {
    headerName: 'X-Frame-Options',
    category: 'FRAMING',
    importance: 'HIGH',
    recommendedValue: 'DENY',
    description: 'Impede que o site seja renderizado dentro de <frame>, <iframe> ou <embed> em sites de terceiros.',
    securityImpact: 'Previne ataques de Clickjacking e UI redressing onde cliques da vítima são sequestrados.',
    cwe: 'CWE-1021',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
  },
  {
    headerName: 'X-Content-Type-Options',
    category: 'SNIFFING',
    importance: 'HIGH',
    recommendedValue: 'nosniff',
    description: 'Obriga o navegador a seguir rigorosamente o Content-Type declarado, sem inferir o formato.',
    securityImpact: 'Evita execução de arquivos de mídia/imagens disfarçados como scripts maliciosos (MIME-Sniffing).',
    cwe: 'CWE-430',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
  },
  {
    headerName: 'Referrer-Policy',
    category: 'PRIVACY',
    importance: 'MEDIUM',
    recommendedValue: 'strict-origin-when-cross-origin',
    description: 'Controla a quantidade de informações de URL enviadas no cabeçalho Referer em navegações externas.',
    securityImpact: 'Impede o vazamento de tokens de autenticação, parâmetros confidenciais ou IDs de sessão expostos na URL.',
    cwe: 'CWE-200',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
  },
  {
    headerName: 'Permissions-Policy',
    category: 'PRIVACY',
    importance: 'MEDIUM',
    recommendedValue: 'camera=(), microphone=(), geolocation=(), payment=()',
    description: 'Desabilita APIs do dispositivo do cliente como microfone, geolocalização e webcam.',
    securityImpact: 'Minimiza superfície de ataque e impede espionagem ou acesso abusivo a hardware do cliente.',
    cwe: 'CWE-250',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
  },
  {
    headerName: 'Cross-Origin-Opener-Policy',
    category: 'ISOLATION',
    importance: 'MEDIUM',
    recommendedValue: 'same-origin',
    description: 'Isola o contexto de navegação superior, garantindo que janelas abertas não compartilhem o event loop.',
    securityImpact: 'Previne ataques Cross-Origin Information Leaks como Spectre via SharedArrayBuffer.',
    cwe: 'CWE-203',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'
  },
  {
    headerName: 'Cross-Origin-Resource-Policy',
    category: 'ISOLATION',
    importance: 'LOW',
    recommendedValue: 'same-origin',
    description: 'Bloqueia o carregamento de recursos estáticos deste site por outros domínios não autorizados.',
    securityImpact: 'Protege contra roubo de arquivos confidenciais através de tags <img> ou <script> cruzadas.',
    cwe: 'CWE-346',
    docUrl: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy'
  }
];

export function evaluateSecurityHeaders(headersMap: Record<string, string>, targetUrl: string = 'https://app.internal.corp'): SecurityHeadersAuditReport {
  // Normalize header keys to lowercase
  const normalized: Record<string, string> = {};
  for (const [k, v] of Object.entries(headersMap)) {
    normalized[k.toLowerCase().trim()] = v.trim();
  }

  const evaluated: HeaderEvaluationResult[] = STANDARD_SECURITY_HEADER_RULES.map(rule => {
    const key = rule.headerName.toLowerCase();
    const val = normalized[key] || null;
    const isPresent = val !== null;
    const issues: string[] = [];
    let score = 0;
    let status: 'OPTIMAL' | 'ACCEPTABLE' | 'WEAK' | 'MISSING' = 'MISSING';
    let isCompliant = false;

    if (!isPresent) {
      issues.push(`O cabeçalho ${rule.headerName} não foi enviado pelo servidor.`);
      status = 'MISSING';
      score = 0;
    } else {
      // Analyze specific headers
      if (key === 'content-security-policy') {
        if (val.includes("'unsafe-inline'") && !val.includes("'nonce-") && !val.includes("'sha256-")) {
          issues.push("Uso inseguro de 'unsafe-inline' sem hash ou nonce permite injeção de código XSS.");
          status = 'WEAK';
          score = 40;
        } else if (val.includes("'unsafe-eval'")) {
          issues.push("Permissão de 'unsafe-eval' habilita o uso de eval() e Function() vulneráveis.");
          status = 'ACCEPTABLE';
          score = 65;
        } else if (val.includes('default-src') || val.includes('script-src')) {
          status = 'OPTIMAL';
          score = 100;
          isCompliant = true;
        } else {
          status = 'ACCEPTABLE';
          score = 70;
        }
      } else if (key === 'strict-transport-security') {
        const hasSub = val.includes('includesubdomains');
        const hasPreload = val.includes('preload');
        const matchAge = val.match(/max-age=(\d+)/i);
        const age = matchAge ? parseInt(matchAge[1], 10) : 0;

        if (age < 15552000) { // < 6 months
          issues.push(`Duração do max-age (${age}s) é inferior ao recomendado (31536000s = 1 ano).`);
          status = 'WEAK';
          score = 50;
        } else if (!hasSub) {
          issues.push('Recomendado adicionar includeSubDomains para proteger todos os subdomínios.');
          status = 'ACCEPTABLE';
          score = 80;
          isCompliant = true;
        } else {
          status = 'OPTIMAL';
          score = 100;
          isCompliant = true;
        }
      } else if (key === 'x-frame-options') {
        if (val.toUpperCase() === 'DENY' || val.toUpperCase() === 'SAMEORIGIN') {
          status = 'OPTIMAL';
          score = 100;
          isCompliant = true;
        } else {
          issues.push(`Valor '${val}' é obsoleto ou inválido.`);
          status = 'WEAK';
          score = 40;
        }
      } else if (key === 'x-content-type-options') {
        if (val.toLowerCase() === 'nosniff') {
          status = 'OPTIMAL';
          score = 100;
          isCompliant = true;
        } else {
          issues.push(`Valor deve ser estritamente 'nosniff'.`);
          status = 'WEAK';
          score = 30;
        }
      } else {
        status = 'OPTIMAL';
        score = 100;
        isCompliant = true;
      }
    }

    return {
      headerName: rule.headerName,
      configuredValue: val,
      isPresent,
      isCompliant,
      score,
      status,
      rule,
      issues,
      remediationSnippet: `${rule.headerName}: ${rule.recommendedValue}`
    };
  });

  // Calculate weighted total score
  let weightedSum = 0;
  let weightTotal = 0;
  evaluated.forEach(h => {
    const weight = h.rule.importance === 'CRITICAL' ? 3 : h.rule.importance === 'HIGH' ? 2 : 1;
    weightedSum += h.score * weight;
    weightTotal += 100 * weight;
  });

  const totalScore = Math.round((weightedSum / (weightTotal || 1)) * 100);

  let grade: HeaderGrade = 'F';
  if (totalScore >= 92) grade = 'A+';
  else if (totalScore >= 80) grade = 'A';
  else if (totalScore >= 65) grade = 'B';
  else if (totalScore >= 50) grade = 'C';
  else if (totalScore >= 35) grade = 'D';

  const criticalMissing = evaluated
    .filter(e => !e.isPresent && (e.rule.importance === 'CRITICAL' || e.rule.importance === 'HIGH'))
    .map(e => e.headerName);

  return {
    targetUrl,
    grade,
    totalScore,
    headersEvaluated: evaluated,
    criticalMissing,
    recommendationsCount: evaluated.filter(e => !e.isCompliant).length,
    serverConfigSnippets: {
      nginx: generateNginxConfig(),
      apache: generateApacheConfig(),
      expressHelmet: generateExpressHelmetConfig(),
      nextConfig: generateNextConfig(),
      caddy: generateCaddyConfig()
    }
  };
}

function generateNginxConfig(): string {
  return `# NGINX Hardened HTTP Security Headers
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;`;
}

function generateApacheConfig(): string {
  return `# Apache HTTP Server (.htaccess / httpd.conf)
<IfModule mod_headers.c>
  Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-Frame-Options "DENY"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  Header always set Cross-Origin-Opener-Policy "same-origin"
</IfModule>`;
}

function generateExpressHelmetConfig(): string {
  return `// Express.js with Helmet Suite
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginOpenerPolicy: { policy: 'same-origin' }
}));`;
}

function generateNextConfig(): string {
  return `// next.config.js (Next.js Security Headers)
const securityHeaders = [
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';" },
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};`;
}

function generateCaddyConfig(): string {
  return `# Caddyfile
example.com {
  header {
    Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';"
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Frame-Options "DENY"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
    Permissions-Policy "camera=(), microphone=()"
  }
}`;
}
