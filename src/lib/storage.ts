/**
 * Safe Storage and Browser Utility Functions
 * Protects against DOMException / SecurityError when running in sandboxed iframes
 * or environments with restricted third-party storage access.
 */

export function safeGetItem(key: string): string | null {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined') {
      return window.localStorage.getItem(key);
    }
  } catch {
    // Access denied in restricted sandbox/iframe
  }
  return null;
}

export function safeSetItem(key: string, value: string): boolean {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined') {
      window.localStorage.setItem(key, value);
      return true;
    }
  } catch {
    // Access denied in restricted sandbox/iframe
  }
  return false;
}

export function safeRemoveItem(key: string): boolean {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined') {
      window.localStorage.removeItem(key);
      return true;
    }
  } catch {
    // Access denied in restricted sandbox/iframe
  }
  return false;
}

export async function safeCopyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Clipboard API may fail in cross-origin iframes
  }

  // Fallback using temporary textarea
  try {
    if (typeof document !== 'undefined') {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      textarea.style.pointerEvents = 'none';
      document.body.appendChild(textarea);
      textarea.select();
      const success = document.execCommand('copy');
      document.body.removeChild(textarea);
      return success;
    }
  } catch {
    // Fallback failed
  }
  return false;
}
