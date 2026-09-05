import { ApiEndpointFinding } from '../types';

/**
 * LinkFinder Engine - Port of PortSwigger js-link-finder & Gerben Javado's LinkFinder
 * Extracts endpoints, relative paths, REST parameters, methods, and full URLs from JavaScript source code.
 */

// Canonical LinkFinder Regex Pattern (Ported from Gerben Javado's LinkFinder for Burp / Python)
const LINKFINDER_REGEX = /(?:"|')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:\/|\.\.\/|\.\/)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"\\']{0,}|))|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{3,}(?:[\?|#][^"\\']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|xml|do)(?:[\?|#][^"\\']{0,}|)))(?:"|')/g;

// Exclusion patterns for static noise, MIME types, CSS properties, regex fragments, and common JS artifacts
const NOISE_FILTER_REGEX = /^(?:text\/|application\/|image\/|multipart\/|audio\/|video\/|font\/|data:|blob:|javascript:|mailto:|tel:|#|\/\{\{)/i;
const EXTENSION_NOISE = /\.(?:png|jpg|jpeg|gif|svg|ico|webp|woff|woff2|ttf|eot|css|scss|less|map)$/i;

// Method detection regexes in caller context around the matched path
const HTTP_METHOD_CONTEXTS: Array<{ method: ApiEndpointFinding['method']; regex: RegExp }> = [
  { method: 'GET', regex: /(?:axios|http|\$http|client|api)\.get\s*\(/i },
  { method: 'POST', regex: /(?:axios|http|\$http|client|api)\.post\s*\(/i },
  { method: 'PUT', regex: /(?:axios|http|\$http|client|api)\.put\s*\(/i },
  { method: 'DELETE', regex: /(?:axios|http|\$http|client|api)\.delete\s*\(/i },
  { method: 'PATCH', regex: /(?:axios|http|\$http|client|api)\.patch\s*\(/i },
  { method: 'GET', regex: /(?:router|app)\.get\s*\(/i },
  { method: 'POST', regex: /(?:router|app)\.post\s*\(/i },
  { method: 'PUT', regex: /(?:router|app)\.put\s*\(/i },
  { method: 'DELETE', regex: /(?:router|app)\.delete\s*\(/i },
  { method: 'PATCH', regex: /(?:router|app)\.patch\s*\(/i },
  { method: 'POST', regex: /method\s*:\s*['"]POST['"]/i },
  { method: 'PUT', regex: /method\s*:\s*['"]PUT['"]/i },
  { method: 'DELETE', regex: /method\s*:\s*['"]DELETE['"]/i },
  { method: 'PATCH', regex: /method\s*:\s*['"]PATCH['"]/i },
  { method: 'GET', regex: /method\s*:\s*['"]GET['"]/i },
  { method: 'POST', regex: /type\s*:\s*['"]POST['"]/i },
  { method: 'GET', regex: /type\s*:\s*['"]GET['"]/i }
];

/**
 * Extracts line number and snippet from content and match index
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
 * Parses query parameters and REST route parameters from a path
 */
export function extractEndpointParameters(rawPath: string): string[] {
  const params = new Set<string>();

  // 1. Query parameters: ?param=val or &param=val or ?param
  const queryIndex = rawPath.indexOf('?');
  if (queryIndex !== -1) {
    const queryString = rawPath.substring(queryIndex + 1).split('#')[0];
    const pairs = queryString.split('&');
    for (const pair of pairs) {
      const key = pair.split('=')[0]?.trim();
      if (key && !key.includes('/') && key.length < 40) {
        params.add(`?${key}`);
      }
    }
  }

  // 2. REST route parameters: :id, :userId, :slug
  const routeParamRegex = /:([a-zA-Z0-9_]+)/g;
  let rpm: RegExpExecArray | null;
  while ((rpm = routeParamRegex.exec(rawPath)) !== null) {
    if (rpm[1]) params.add(`:${rpm[1]}`);
  }

  // 3. Curly brace parameters: {id}, {userId}
  const curlyParamRegex = /\{([a-zA-Z0-9_]+)\}/g;
  let cpm: RegExpExecArray | null;
  while ((cpm = curlyParamRegex.exec(rawPath)) !== null) {
    if (cpm[1]) params.add(`{${cpm[1]}}`);
  }

  // 4. Bracket parameters: [id], [slug]
  const bracketParamRegex = /\[([a-zA-Z0-9_]+)\]/g;
  let bpm: RegExpExecArray | null;
  while ((bpm = bracketParamRegex.exec(rawPath)) !== null) {
    if (bpm[1]) params.add(`[${bpm[1]}]`);
  }

  return Array.from(params);
}

/**
 * Categorizes the endpoint into LinkFinder scope and type
 */
export function classifyEndpointScope(rawPath: string): {
  urlType: NonNullable<ApiEndpointFinding['urlType']>;
  scope: NonNullable<ApiEndpointFinding['scope']>;
  isInternalOrAdmin: boolean;
} {
  const lower = rawPath.toLowerCase();

  // Check if internal or administrative
  const isInternalOrAdmin = 
    /admin|internal|superadmin|debug|metrics|actuator|secret|management|root|eval|shell|dashboard\/internal/i.test(lower) ||
    lower.includes('10.') || 
    lower.includes('192.168.') || 
    lower.includes('172.16.') || 
    lower.includes('localhost') || 
    lower.includes('.internal') || 
    lower.includes('.local');

  // WebSocket
  if (lower.startsWith('ws://') || lower.startsWith('wss://')) {
    return {
      urlType: 'WEBSOCKET',
      scope: isInternalOrAdmin ? 'INTERNAL' : 'IN_SCOPE',
      isInternalOrAdmin
    };
  }

  // GraphQL
  if (lower.includes('/graphql') || lower.endsWith('/gql')) {
    return {
      urlType: 'GRAPHQL',
      scope: isInternalOrAdmin ? 'INTERNAL' : 'IN_SCOPE',
      isInternalOrAdmin
    };
  }

  // Static Assets
  if (EXTENSION_NOISE.test(lower)) {
    return {
      urlType: 'STATIC_ASSET',
      scope: lower.includes('cdn') || lower.includes('unpkg') ? 'CDN' : 'IN_SCOPE',
      isInternalOrAdmin
    };
  }

  // Full URLs
  if (lower.startsWith('http://') || lower.startsWith('https://') || lower.startsWith('//')) {
    const isCdn = lower.includes('cdn') || lower.includes('unpkg') || lower.includes('cdnjs') || lower.includes('googleapis.com');
    const isInternal = isInternalOrAdmin || lower.includes('.internal') || lower.includes('localhost');
    return {
      urlType: 'FULL_URL',
      scope: isInternal ? 'INTERNAL' : (isCdn ? 'CDN' : 'EXTERNAL'),
      isInternalOrAdmin
    };
  }

  // Relative API paths
  return {
    urlType: 'RELATIVE_PATH',
    scope: isInternalOrAdmin ? 'INTERNAL' : 'IN_SCOPE',
    isInternalOrAdmin
  };
}

/**
 * Generates an executable cURL command for testing this endpoint
 */
export function generateCurlCommand(path: string, method: ApiEndpointFinding['method'] = 'GET'): string {
  const effectiveMethod = method || 'GET';
  let targetUrl = path;
  if (targetUrl.startsWith('/')) {
    targetUrl = `https://target-domain.com${targetUrl}`;
  } else if (targetUrl.startsWith('//')) {
    targetUrl = `https:${targetUrl}`;
  }

  const parts = [
    `curl -i -s -k -X ${effectiveMethod}`,
    `"${targetUrl}"`,
    `-H "User-Agent: Mozilla/5.0 (LinkFinder SecScan SAST)"`,
    `-H "Accept: application/json, text/plain, */*"`
  ];

  if (effectiveMethod === 'POST' || effectiveMethod === 'PUT' || effectiveMethod === 'PATCH') {
    parts.push(`-H "Content-Type: application/json"`);
    parts.push(`-d '{"probe": "secscan_test"}'`);
  }

  return parts.join(' \\\n  ');
}

/**
 * LinkFinder Extraction Engine
 * Runs against a single source file and returns structured ApiEndpointFinding array
 */
export function extractLinkFinderEndpoints(filePath: string, content: string): ApiEndpointFinding[] {
  const results: ApiEndpointFinding[] = [];
  const seenPaths = new Set<string>();

  // 1. First pass: explicit REST calls with HTTP methods (axios, fetch, router, app)
  const explicitMethodRegex = /(?:app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|axios\.(get|post|put|delete|patch)|\$http\.(get|post|put|delete|patch)|fetch)\s*\(\s*['"`]([^'"`]+)['"`]/gi;
  let explicitMatch: RegExpExecArray | null;
  while ((explicitMatch = explicitMethodRegex.exec(content)) !== null) {
    const methodStr = (explicitMatch[1] || explicitMatch[2] || explicitMatch[3] || explicitMatch[4] || 'GET').toUpperCase();
    const rawPath = explicitMatch[5]?.trim();
    if (!rawPath || rawPath.length < 2 || NOISE_FILTER_REGEX.test(rawPath)) continue;

    const { line, snippet } = getLineInfo(content, explicitMatch.index);
    const { urlType, scope, isInternalOrAdmin } = classifyEndpointScope(rawPath);
    const params = extractEndpointParameters(rawPath);
    const method = methodStr as ApiEndpointFinding['method'];

    const key = `${method}:${rawPath}:${filePath}`;
    if (!seenPaths.has(key)) {
      seenPaths.add(key);
      results.push({
        id: `ep-${results.length + 1}-${Math.random().toString(36).substring(2, 6)}`,
        file: filePath,
        line,
        method,
        path: rawPath,
        isInternalOrAdmin,
        snippet,
        urlType,
        scope,
        params,
        sourceTool: 'LINK_FINDER',
        curlCommand: generateCurlCommand(rawPath, method)
      });
    }
  }

  // 2. Second pass: LinkFinder regex for all endpoints & URIs
  LINKFINDER_REGEX.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = LINKFINDER_REGEX.exec(content)) !== null) {
    const rawMatch = (match[1] || '').trim();
    if (!rawMatch || rawMatch.length < 2) continue;

    // Filter out common false positives and noise
    if (
      NOISE_FILTER_REGEX.test(rawMatch) ||
      rawMatch.startsWith('===') ||
      rawMatch.startsWith('---') ||
      rawMatch.includes(' ') ||
      rawMatch.includes('\n') ||
      rawMatch.length > 250
    ) {
      continue;
    }

    // Must start with /, http, ws, // or have a file extension or path slash
    if (
      !rawMatch.startsWith('/') &&
      !rawMatch.startsWith('http://') &&
      !rawMatch.startsWith('https://') &&
      !rawMatch.startsWith('ws://') &&
      !rawMatch.startsWith('wss://') &&
      !rawMatch.startsWith('//') &&
      !rawMatch.includes('/api/') &&
      !rawMatch.includes('/v1/') &&
      !rawMatch.includes('/v2/')
    ) {
      continue;
    }

    // Determine calling method by examining surrounding 80 characters
    const surroundingStart = Math.max(0, match.index - 80);
    const surroundingEnd = Math.min(content.length, match.index + rawMatch.length + 80);
    const contextSnippet = content.substring(surroundingStart, surroundingEnd);

    let detectedMethod: ApiEndpointFinding['method'] = 'GET';
    for (const ctx of HTTP_METHOD_CONTEXTS) {
      if (ctx.regex.test(contextSnippet)) {
        detectedMethod = ctx.method;
        break;
      }
    }

    const { line, snippet } = getLineInfo(content, match.index);
    const { urlType, scope, isInternalOrAdmin } = classifyEndpointScope(rawMatch);
    const params = extractEndpointParameters(rawMatch);

    const key = `${detectedMethod}:${rawMatch}:${filePath}`;
    if (!seenPaths.has(key)) {
      seenPaths.add(key);
      results.push({
        id: `ep-${results.length + 1}-${Math.random().toString(36).substring(2, 6)}`,
        file: filePath,
        line,
        method: detectedMethod,
        path: rawMatch,
        isInternalOrAdmin,
        snippet,
        urlType,
        scope,
        params,
        sourceTool: 'LINK_FINDER',
        curlCommand: generateCurlCommand(rawMatch, detectedMethod)
      });
    }
  }

  return results;
}

/**
 * Generates Burp Suite Scope XML format
 */
export function exportToBurpScope(endpoints: ApiEndpointFinding[]): string {
  const hosts = new Set<string>();
  const paths = new Set<string>();

  for (const ep of endpoints) {
    if (ep.path.startsWith('http://') || ep.path.startsWith('https://')) {
      try {
        const url = new URL(ep.path);
        hosts.add(url.hostname);
      } catch {
        // invalid URL
      }
    } else if (ep.path.startsWith('/')) {
      paths.add(ep.path.split('?')[0]);
    }
  }

  return `<?xml version="1.0" encoding="UTF-8"?>
<!-- Generated by SecScan LinkFinder Engine (PortSwigger js-link-finder format) -->
<target>
  <scope>
    <include>
      <enabled>true</enabled>
      <protocol>https</protocol>
      <host>.*</host>
      <file>${Array.from(paths).slice(0, 50).map(p => `^${p.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1")}`).join('|') || '^/api/.*'}</file>
    </include>
  </scope>
  <endpoints>
${endpoints.map(ep => `    <endpoint method="${ep.method || 'GET'}" scope="${ep.scope || 'IN_SCOPE'}" path="${ep.path.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}" />`).join('\n')}
  </endpoints>
</target>`;
}

/**
 * Generates raw clean list of unique URLs/paths
 */
export function exportToCleanUrlList(endpoints: ApiEndpointFinding[]): string {
  const unique = Array.from(new Set(endpoints.map(e => `${e.method || 'GET'} ${e.path}`)));
  return unique.join('\n');
}
