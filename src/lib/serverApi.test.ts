import { describe, expect, it } from 'vitest';
import { readServerJson, ServerApiUnavailableError } from './serverApi';

function responseWith(body: string, contentType: string, status = 200): Response {
  return new Response(body, { status, headers: { 'content-type': contentType } });
}

describe('resposta /api no site estático', () => {
  it('recusa HTML do fallback da SPA', async () => {
    const response = responseWith('<!doctype html><html></html>', 'text/html; charset=utf-8');
    await expect(readServerJson(response)).rejects.toBeInstanceOf(ServerApiUnavailableError);
  });

  it('lê JSON do servidor', async () => {
    const response = responseWith('{"success":true}', 'application/json');
    await expect(readServerJson<{ success: boolean }>(response)).resolves.toEqual({ success: true });
  });
});
