import {
  JsMinerResults,
  SourceMapFinding,
  CloudBucketFinding,
  JwtTokenFinding,
  BundledDependencyFinding,
  DangerousSinkFinding,
  SeverityLevel
} from '../types';

/**
 * JS-Miner Engine - Port of PortSwigger's js-miner Burp Suite extension
 * Specializes in mining JavaScript source code for:
 * 1. Source Maps & Exposed Source References
 * 2. Cloud Storage Buckets (AWS S3, Google Cloud Storage, Azure Blob, Firebase, DigitalOcean)
 * 3. Exposed JWT Tokens (with payload decoding & vulnerability checks)
 * 4. Bundled Libraries / Dependencies with Known CVE Advisories
 * 5. Dangerous DOM Sinks (eval, innerHTML, document.write, postMessage, insecure storage)
 */

// 1. Cloud Storage Detection Patterns
const BUCKET_PATTERNS = [
  // AWS S3
  {
    provider: 'AWS_S3' as const,
    regex: /(?:https?:\/\/)?([a-zA-Z0-9.\-_]{3,63})\.s3(?:[.-](?:[a-zA-Z0-9\-]+))?\.amazonaws\.com/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: match[1],
      url: match[0].startsWith('http') ? match[0] : `https://${match[0]}`,
      risk: 'AWS S3 Bucket público ou interno referenciado no front-end. Risco de permissões mal configuradas (ListBucket / Public Read/Write).',
      checkCommand: `aws s3 ls s3://${match[1]} --no-sign-request`
    })
  },
  {
    provider: 'AWS_S3' as const,
    regex: /s3:\/\/([a-zA-Z0-9.\-_]{3,63})/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: match[1],
      url: `s3://${match[1]}`,
      risk: 'URI s3:// interna codificada no bundle. Risco de exposição de estrutura de dados e arquivos corporativos.',
      checkCommand: `aws s3 ls s3://${match[1]} --no-sign-request`
    })
  },
  // Google Cloud Storage
  {
    provider: 'GOOGLE_CLOUD_STORAGE' as const,
    regex: /(?:https?:\/\/)?storage\.googleapis\.com\/([a-zA-Z0-9.\-_]{3,63})/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: match[1],
      url: match[0].startsWith('http') ? match[0] : `https://${match[0]}`,
      risk: 'Google Cloud Storage Bucket referenciado no cliente. Verifique se as ACLs permitem leitura anônima (`allUsers`).',
      checkCommand: `gsutil ls -b gs://${match[1]}`
    })
  },
  {
    provider: 'GOOGLE_CLOUD_STORAGE' as const,
    regex: /gs:\/\/([a-zA-Z0-9.\-_]{3,63})/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: match[1],
      url: `gs://${match[1]}`,
      risk: 'URI gs:// do Google Cloud Storage em código-fonte. Pode expor artefatos de build ou logs privados.',
      checkCommand: `gsutil ls -b gs://${match[1]}`
    })
  },
  // Azure Blob Storage
  {
    provider: 'AZURE_BLOB' as const,
    regex: /(?:https?:\/\/)?([a-zA-Z0-9]{3,24})\.blob\.core\.windows\.net\/([a-zA-Z0-9\-_]{3,63})/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: `${match[1]}/${match[2]}`,
      url: match[0].startsWith('http') ? match[0] : `https://${match[0]}`,
      risk: 'Container de Azure Blob Storage referenciado diretamente no bundle JS. Risco de acesso anônimo ao container.',
      checkCommand: `curl -s -i "https://${match[1]}.blob.core.windows.net/${match[2]}?restype=container&comp=list"`
    })
  },
  // DigitalOcean Spaces
  {
    provider: 'DIGITAL_OCEAN' as const,
    regex: /(?:https?:\/\/)?([a-zA-Z0-9.\-_]{3,63})\.([a-zA-Z0-9\-]+)\.digitaloceanspaces\.com/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: match[1],
      url: match[0].startsWith('http') ? match[0] : `https://${match[0]}`,
      risk: 'DigitalOcean Space referenciado no script. Pode conter backups e dados confidenciais com leitura pública.',
      checkCommand: `curl -s -i "https://${match[1]}.${match[2]}.digitaloceanspaces.com"`
    })
  },
  // Firebase Storage
  {
    provider: 'FIREBASE' as const,
    regex: /(?:https?:\/\/)?firebasestorage\.googleapis\.com\/v0\/b\/([a-zA-Z0-9.\-_]+)/gi,
    builder: (match: RegExpExecArray) => ({
      bucketName: match[1],
      url: match[0].startsWith('http') ? match[0] : `https://${match[0]}`,
      risk: 'Firebase Storage Bucket referenciado no cliente. Verifique se as Firebase Security Rules protegem arquivos privados.',
      checkCommand: `curl -s -i "${match[0]}"`
    })
  }
];

// 2. Dangerous DOM Sinks & Injection Patterns (js-miner signature database)
const DANGEROUS_SINKS_PATTERNS: Array<{
  type: DangerousSinkFinding['sinkType'];
  regex: RegExp;
  severity: SeverityLevel;
  description: string;
  remediation: string;
}> = [
  {
    type: 'EVAL',
    regex: /(?:window\.)?eval\s*\(([^)]+)\)/g,
    severity: 'CRITICAL',
    description: 'Uso direto da função nativa `eval()`. Permite execução arbitrária de código JavaScript (DOM-based Code Execution).',
    remediation: 'Substitua `eval()` por analisadores seguros como `JSON.parse()` ou arquiteturas declarativas.'
  },
  {
    type: 'FUNCTION_CONSTRUCTOR',
    regex: /new\s+Function\s*\([^)]*\)/g,
    severity: 'HIGH',
    description: 'Instanciação dinâmica via `new Function(...)`. Equivalente a `eval()`, interpretando strings arbitrárias como código executável.',
    remediation: 'Evite gerar funções em runtime a partir de strings ou templates.'
  },
  {
    type: 'INNER_HTML',
    regex: /\.(?:innerHTML|outerHTML)\s*=\s*([^;\n]+)/g,
    severity: 'HIGH',
    description: 'Atribuição direta a `innerHTML` ou `outerHTML`. Se o valor contiver dados do usuário ou query params, pode gerar DOM-based XSS.',
    remediation: 'Utilize `textContent`, `innerText` ou bibliotecas de sanitização como DOMPurify.'
  },
  {
    type: 'DOCUMENT_WRITE',
    regex: /document\.(?:write|writeln)\s*\(/g,
    severity: 'HIGH',
    description: 'Chamada a `document.write()`. Prática obsoleta e altamente vulnerável a injeções de script de primeiro nível.',
    remediation: 'Substitua por manipulação segura de nós do DOM (`document.createElement` e `appendChild`).'
  },
  {
    type: 'POST_MESSAGE',
    regex: /window\.postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/g,
    severity: 'MEDIUM',
    description: 'Envio de mensagem via `postMessage` com targetOrigin coringa ("*"). Qualquer janela/iframe incorporador pode interceptar os dados.',
    remediation: 'Especifique o domínio de origem exato esperado (ex: "https://minhaempresa.com") em vez de "*".'
  },
  {
    type: 'INSECURE_STORAGE',
    regex: /(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"`](?:token|auth|jwt|password|secret|key|access_token|session)/gi,
    severity: 'MEDIUM',
    description: 'Armazenamento de tokens ou credenciais confidenciais em `localStorage` ou `sessionStorage`. Dados expostos a qualquer XSS.',
    remediation: 'Prefira armazenar sessões em cookies HttpOnly e Secure com flag SameSite.'
  }
];

// 3. Known Bundled Libraries Signatures Database (js-miner)
const KNOWN_LIBRARIES = [
  {
    name: 'jQuery',
    regex: /jQuery\s+JavaScript\s+Library\s+v([0-9]+\.[0-9]+\.[0-9]+)/i,
    check: (ver: string) => {
      if (ver.startsWith('1.') || ver.startsWith('2.') || (ver.startsWith('3.') && parseInt(ver.split('.')[1] || '0', 10) < 5)) {
        return {
          status: 'VULNERABLE' as const,
          cve: 'CVE-2020-11022 / CVE-2015-9251',
          desc: `Versão ${ver} do jQuery é vulnerável a DOM XSS via métodos de manipulação de tags HTML (ex: $.htmlPrefilter).`
        };
      }
      return { status: 'OK' as const, desc: `jQuery v${ver} em conformidade com versões modernas.` };
    }
  },
  {
    name: 'Lodash',
    regex: /(?:lodash|Lodash)\s+(?:Modular\s+Utilities|v)?([0-9]+\.[0-9]+\.[0-9]+)/i,
    check: (ver: string) => {
      const parts = ver.split('.').map(n => parseInt(n, 10));
      if (parts[0] < 4 || (parts[0] === 4 && parts[1] < 17) || (parts[0] === 4 && parts[1] === 17 && parts[2] < 21)) {
        return {
          status: 'VULNERABLE' as const,
          cve: 'CVE-2019-10744 / CVE-2020-8203',
          desc: `Versão ${ver} do Lodash possui vulnerabilidade de Prototype Pollution crítica em rotas como _.merge e _.zipObjectDeep.`
        };
      }
      return { status: 'OK' as const, desc: `Lodash v${ver} atualizado.` };
    }
  },
  {
    name: 'Moment.js',
    regex: /moment\.js(?:\s+version\s+)?[:\s]+([0-9]+\.[0-9]+\.[0-9]+)/i,
    check: (ver: string) => {
      const parts = ver.split('.').map(n => parseInt(n, 10));
      if (parts[0] < 2 || (parts[0] === 2 && parts[1] < 29) || (parts[0] === 2 && parts[1] === 29 && parts[2] < 4)) {
        return {
          status: 'VULNERABLE' as const,
          cve: 'CVE-2022-31129 / CVE-2022-24785',
          desc: `Versão ${ver} do Moment.js sofre de vulnerabilidade de ReDoS (Regular Expression Denial of Service) e Path Traversal.`
        };
      }
      return { status: 'OUTDATED' as const, desc: `Moment.js v${ver} é um projeto legado (em modo de manutenção). Recomenda-se date-fns ou Intl.` };
    }
  },
  {
    name: 'AngularJS',
    regex: /AngularJS\s+v([0-9]+\.[0-9]+\.[0-9]+)/i,
    check: (ver: string) => {
      return {
        status: 'VULNERABLE' as const,
        cve: 'CVE-2019-10768 / End of Life',
        desc: `AngularJS 1.x (v${ver}) atingiu End-of-Life oficial e possui múltiplas vulnerabilidades de Sandbox Escape e Prototype Pollution.`
      };
    }
  },
  {
    name: 'Axios',
    regex: /axios\s+v([0-9]+\.[0-9]+\.[0-9]+)/i,
    check: (ver: string) => {
      const parts = ver.split('.').map(n => parseInt(n, 10));
      if (parts[0] === 0 && parts[1] < 21) {
        return {
          status: 'VULNERABLE' as const,
          cve: 'CVE-2020-28168',
          desc: `Versão ${ver} do Axios sofre de SSRF via parâmetros de requisição com redirecionamento não higienizado.`
        };
      }
      return { status: 'OK' as const, desc: `Axios v${ver} está em conformidade.` };
    }
  }
];

/**
 * Safely decodes base64 URL string
 */
function safeBase64UrlDecode(str: string): string | null {
  try {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return atob(base64);
  } catch {
    return null;
  }
}

/**
 * Extracts line number and snippet for a given string index
 */
function getLineInfo(content: string, index: number): { line: number; snippet: string } {
  const upToIndex = content.substring(0, index);
  const lines = upToIndex.split('\n');
  const line = lines.length;
  const allLines = content.split('\n');
  const snippet = (allLines[line - 1] || '').trim();
  return { line, snippet };
}

/**
 * JS-Miner Core Analyzer
 * Runs comprehensive analysis of JS files to extract source maps, buckets, JWTs, dependencies, and sinks
 */
export function analyzeWithJsMiner(filePath: string, content: string): {
  sourceMaps: SourceMapFinding[];
  cloudBuckets: CloudBucketFinding[];
  jwtTokens: JwtTokenFinding[];
  dependencies: BundledDependencyFinding[];
  dangerousSinks: DangerousSinkFinding[];
} {
  const sourceMaps: SourceMapFinding[] = [];
  const cloudBuckets: CloudBucketFinding[] = [];
  const jwtTokens: JwtTokenFinding[] = [];
  const dependencies: BundledDependencyFinding[] = [];
  const dangerousSinks: DangerousSinkFinding[] = [];

  // ==========================================
  // 1. SOURCE MAP MINING
  // ==========================================
  const smRegex = /\/\/#\s*sourceMappingURL=([^\s'"]+)/g;
  let smMatch: RegExpExecArray | null;
  while ((smMatch = smRegex.exec(content)) !== null) {
    const rawUrl = smMatch[1] || '';
    const { line, snippet } = getLineInfo(content, smMatch.index);

    let type: SourceMapFinding['type'] = 'EXTERNAL_FILE';
    let riskDescription = 'Referência a arquivo .map externo. Permite que atacantes baixem e descompactem todo o código-fonte original, componentes e comentários internos da aplicação.';

    if (rawUrl.startsWith('data:application/json') || rawUrl.startsWith('data:text/plain')) {
      type = 'INLINE_BASE64';
      riskDescription = 'Source Map embutido diretamente em Base64 dentro do bundle de produção! O código original está 100% exposto no próprio navegador.';
    }

    sourceMaps.push({
      id: `sm-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      file: filePath,
      line,
      url: rawUrl.length > 80 ? rawUrl.substring(0, 77) + '...' : rawUrl,
      type,
      snippet,
      riskDescription
    });
  }

  // ==========================================
  // 2. CLOUD BUCKET DISCOVERY
  // ==========================================
  for (const bucketDef of BUCKET_PATTERNS) {
    bucketDef.regex.lastIndex = 0;
    let bMatch: RegExpExecArray | null;
    while ((bMatch = bucketDef.regex.exec(content)) !== null) {
      const { line, snippet } = getLineInfo(content, bMatch.index);
      const built = bucketDef.builder(bMatch);

      // Avoid duplicates
      const exists = cloudBuckets.some(b => b.bucketName === built.bucketName && b.file === filePath);
      if (!exists) {
        cloudBuckets.push({
          id: `cb-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          provider: bucketDef.provider,
          bucketName: built.bucketName,
          url: built.url,
          file: filePath,
          line,
          snippet,
          riskDescription: built.risk,
          checkCommand: built.checkCommand
        });
      }
    }
  }

  // ==========================================
  // 3. JWT TOKEN MINING & PAYLOAD DECODING
  // ==========================================
  const jwtRegex = /\b(ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g;
  let jwtMatch: RegExpExecArray | null;
  while ((jwtMatch = jwtRegex.exec(content)) !== null) {
    const rawToken = jwtMatch[1];
    const parts = rawToken.split('.');
    if (parts.length === 3) {
      const headerJson = safeBase64UrlDecode(parts[0]);
      const payloadJson = safeBase64UrlDecode(parts[1]);

      if (headerJson && payloadJson) {
        try {
          const header = JSON.parse(headerJson) as Record<string, unknown>;
          const payload = JSON.parse(payloadJson) as Record<string, unknown>;
          const { line } = getLineInfo(content, jwtMatch.index);

          const risks: string[] = [];
          const algorithm = String(header.alg || 'none');

          if (algorithm.toLowerCase() === 'none') {
            risks.push('CRÍTICO: Algoritmo "none" configurado no JWT (permite forjação de assinaturas arbitrárias).');
          }

          let isExpired = false;
          let expiresAt: string | undefined;
          if (typeof payload.exp === 'number') {
            const expMs = payload.exp * 1000;
            isExpired = Date.now() > expMs;
            expiresAt = new Date(expMs).toLocaleString();
            if (isExpired) {
              risks.push(`Token expirado em ${expiresAt}, porém exposto estaticamente no código.`);
            }
          }

          const roles: string[] = [];
          if (typeof payload.role === 'string') roles.push(payload.role);
          if (Array.isArray(payload.roles)) roles.push(...payload.roles.map(String));
          if (payload.admin === true || payload.is_admin === true) roles.push('admin');

          if (roles.some(r => /admin|root|internal|system/i.test(r))) {
            risks.push('ALTO: O token possui privilégios administrativos ou de sistema declarados no payload.');
          }

          jwtTokens.push({
            id: `jwt-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            token: `${rawToken.substring(0, 16)}...${rawToken.substring(rawToken.length - 8)}`,
            file: filePath,
            line,
            header,
            payload,
            algorithm,
            isExpired,
            expiresAt,
            issuer: typeof payload.iss === 'string' ? payload.iss : undefined,
            subject: typeof payload.sub === 'string' ? payload.sub : undefined,
            roles: roles.length > 0 ? roles : undefined,
            risks
          });
        } catch {
          // not valid json payload
        }
      }
    }
  }

  // ==========================================
  // 4. BUNDLED LIBRARIES / SOFTWARE COMPOSITION
  // ==========================================
  for (const lib of KNOWN_LIBRARIES) {
    lib.regex.lastIndex = 0;
    const match = lib.regex.exec(content);
    if (match && match[1]) {
      const version = match[1];
      const { line } = getLineInfo(content, match.index);
      const assessment = lib.check(version);

      dependencies.push({
        id: `lib-${lib.name.toLowerCase()}-${Math.random().toString(36).substring(2, 6)}`,
        name: lib.name,
        version,
        file: filePath,
        line,
        confidence: 'HIGH',
        status: assessment.status,
        cveAdvisory: (assessment as { cve?: string }).cve,
        description: assessment.desc
      });
    }
  }

  // ==========================================
  // 5. DANGEROUS DOM SINKS (DOM XSS / CODE EXECUTION)
  // ==========================================
  for (const sink of DANGEROUS_SINKS_PATTERNS) {
    sink.regex.lastIndex = 0;
    let sMatch: RegExpExecArray | null;
    while ((sMatch = sink.regex.exec(content)) !== null) {
      const { line, snippet } = getLineInfo(content, sMatch.index);

      // Simple deduplication per line & type
      const exists = dangerousSinks.some(d => d.file === filePath && d.line === line && d.sinkType === sink.type);
      if (!exists) {
        dangerousSinks.push({
          id: `sink-${sink.type.toLowerCase()}-${Date.now()}-${Math.random().toString(36).substring(2, 5)}`,
          sinkType: sink.type,
          file: filePath,
          line,
          snippet,
          severity: sink.severity,
          description: sink.description,
          remediation: sink.remediation
        });
      }
    }
  }

  return {
    sourceMaps,
    cloudBuckets,
    jwtTokens,
    dependencies,
    dangerousSinks
  };
}
