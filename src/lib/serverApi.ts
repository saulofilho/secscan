export class ServerApiUnavailableError extends Error {
  constructor(language: 'pt' | 'en' | 'es' = 'pt') {
    super(serverApiUnavailableMessage(language));
    this.name = 'ServerApiUnavailableError';
  }
}

export function serverApiUnavailableMessage(language: 'pt' | 'en' | 'es' = 'pt'): string {
  if (language === 'en') {
    return 'This action needs the Secscan server. The published site only serves the interface.';
  }
  if (language === 'es') {
    return 'Esta función necesita el servidor Secscan. El sitio publicado solo entrega la interfaz.';
  }
  return 'Esta função precisa do servidor Secscan. O site publicado só entrega a interface.';
}

export async function readServerJson<T>(response: Response, language: 'pt' | 'en' | 'es' = 'pt'): Promise<T> {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    throw new ServerApiUnavailableError(language);
  }
  return response.json() as Promise<T>;
}
