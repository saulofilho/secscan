import { lookup } from 'node:dns/promises';
import net from 'node:net';

export class UrlIngestRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UrlIngestRejected';
  }
}

const BLOCKED_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
]);

const BLOCKED_SUFFIXES = ['.local', '.localhost', '.internal', '.localdomain'];

export function isBlockedIpAddress(address: string): boolean {
  const ip = address.toLowerCase().replace(/^\[|\]$/g, '');
  if (ip.startsWith('::ffff:')) {
    return isBlockedIpAddress(ip.slice('::ffff:'.length));
  }

  if (net.isIP(ip) === 4) {
    const parts = ip.split('.').map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return true;
    }
    const [a, b, c] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0 && c === 0) return true;
    if (a === 192 && b === 0 && c === 2) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    if (a >= 224) return true;
    return false;
  }

  if (net.isIP(ip) === 6) {
    if (ip === '::' || ip === '::1') return true;
    const first = ip.split(':').find((part) => part.length > 0) || '0';
    const value = Number.parseInt(first, 16);
    if (!Number.isFinite(value)) return true;
    if ((value & 0xfe00) === 0xfc00) return true;
    if ((value & 0xffc0) === 0xfe80) return true;
    if ((value & 0xff00) === 0xff00) return true;
    return false;
  }

  return true;
}

function isAmbiguousNumericHost(hostname: string): boolean {
  if (/^\d+$/.test(hostname)) return true;
  if (!/^\d+(\.\d+){0,3}$/.test(hostname)) return false;
  const parts = hostname.split('.');
  if (parts.length !== 4) return true;
  return parts.some((part) => part.length > 1 && part.startsWith('0'));
}

export async function resolvePublicHttpUrl(input: string): Promise<URL> {
  let target = input.trim();
  if (!/^https?:\/\//i.test(target)) {
    target = `https://${target}`;
  }

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new UrlIngestRejected('Formato de URL inválido.');
  }

  if (url.username || url.password) {
    throw new UrlIngestRejected('URL com credencial embutida não é aceita.');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new UrlIngestRejected('Somente HTTP e HTTPS são aceitos.');
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '');
  if (!host || BLOCKED_HOSTS.has(host) || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new UrlIngestRejected('Host local ou de metadata não é aceito.');
  }
  if (isAmbiguousNumericHost(host) || (net.isIP(host) !== 0 && isBlockedIpAddress(host))) {
    throw new UrlIngestRejected('Endereço de rede privada ou reservada não é aceito.');
  }

  if (net.isIP(host) === 0) {
    let records: { address: string }[];
    try {
      records = await lookup(host, { all: true, verbatim: true });
    } catch {
      throw new UrlIngestRejected('Não foi possível resolver o host.');
    }
    if (records.length === 0 || records.some((record) => isBlockedIpAddress(record.address))) {
      throw new UrlIngestRejected('O host resolve para um endereço de rede privada ou reservada.');
    }
  }

  return url;
}

export interface PublicFetchOk {
  kind: 'ok';
  response: Response;
  finalUrl: URL;
}

export async function fetchPublicUrl(start: URL, timeoutMs: number, maxHops = 2): Promise<PublicFetchOk> {
  let current = await resolvePublicHttpUrl(start.href);

  for (let hop = 0; hop <= maxHops; hop += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(current.href, {
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'SecScan-Auditor/0.1',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8',
        },
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) {
          throw new UrlIngestRejected('Redirecionamento sem destino.');
        }
        if (hop === maxHops) {
          throw new UrlIngestRejected('Redirecionamento excedeu o limite.');
        }
        current = await resolvePublicHttpUrl(new URL(location, current).href);
        continue;
      }

      return { kind: 'ok', response, finalUrl: current };
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new UrlIngestRejected('Redirecionamento excedeu o limite.');
}
