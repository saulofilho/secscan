import { lookup } from 'node:dns/promises';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { isBlockedIpAddress, resolvePublicHttpUrl, UrlIngestRejected } from './urlIngestGuard';

vi.mock('node:dns/promises', () => ({
  lookup: vi.fn(),
}));

const mockedLookup = vi.mocked(lookup);

describe('url ingest guard', () => {
  beforeEach(() => {
    mockedLookup.mockReset();
  });

  it('recusa loopback, link-local, rede privada e metadata', async () => {
    const blocked = [
      'http://127.0.0.1/latest',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.1.2.3/',
      'http://192.168.0.8/',
      'http://172.16.0.4/',
      'http://[::1]/',
      'http://localhost/admin',
      'http://metadata.google.internal/',
      'http://127.1/',
      'http://2130706433/',
    ];

    for (const url of blocked) {
      await expect(resolvePublicHttpUrl(url)).rejects.toBeInstanceOf(UrlIngestRejected);
    }
    expect(mockedLookup).not.toHaveBeenCalled();
  });

  it('recusa host que resolve para endereço privado', async () => {
    mockedLookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }] as never);
    await expect(resolvePublicHttpUrl('https://rebind.example')).rejects.toBeInstanceOf(UrlIngestRejected);
  });

  it('aceita host cujo DNS só devolve endereço público', async () => {
    mockedLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    const url = await resolvePublicHttpUrl('example.com/health');
    expect(url.href).toBe('https://example.com/health');
  });

  it('classifica IPv6 local e multicast como bloqueados', () => {
    expect(isBlockedIpAddress('fe80::1')).toBe(true);
    expect(isBlockedIpAddress('fd00::1')).toBe(true);
    expect(isBlockedIpAddress('ff02::1')).toBe(true);
    expect(isBlockedIpAddress('::ffff:10.0.0.2')).toBe(true);
    expect(isBlockedIpAddress('8.8.8.8')).toBe(false);
  });
});
