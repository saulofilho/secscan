import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';

export type ToastType = 'error' | 'success' | 'warning' | 'info';

export interface ToastItem {
  id: string;
  type: ToastType;
  title?: string;
  message: string;
  details?: string;
  duration?: number;
  timestamp: number;
}

export interface ToastOptions {
  title?: string;
  details?: string;
  duration?: number;
}

interface ToastContextValue {
  toasts: ToastItem[];
  showToast: (type: ToastType, message: string, options?: ToastOptions) => string;
  error: (message: string, options?: ToastOptions) => string;
  success: (message: string, options?: ToastOptions) => string;
  warning: (message: string, options?: ToastOptions) => string;
  info: (message: string, options?: ToastOptions) => string;
  dismiss: (id: string) => void;
  clearAll: () => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

// Global instance bridge so toast can also be called outside React lifecycle if needed
let globalToastBridge: ((type: ToastType, message: string, options?: ToastOptions) => string) | null = null;

export const toast = {
  error: (message: string, options?: ToastOptions) => globalToastBridge?.('error', message, options) ?? '',
  success: (message: string, options?: ToastOptions) => globalToastBridge?.('success', message, options) ?? '',
  warning: (message: string, options?: ToastOptions) => globalToastBridge?.('warning', message, options) ?? '',
  info: (message: string, options?: ToastOptions) => globalToastBridge?.('info', message, options) ?? ''
};

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const lastErrorRef = useRef<{ msg: string; time: number }>({ msg: '', time: 0 });

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setToasts([]);
  }, []);

  const showToast = useCallback((type: ToastType, message: string, options?: ToastOptions): string => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const defaultDuration = type === 'error' ? 8000 : type === 'warning' ? 6000 : 4500;
    const duration = options?.duration !== undefined ? options.duration : defaultDuration;

    const newItem: ToastItem = {
      id,
      type,
      title: options?.title,
      message,
      details: options?.details,
      duration,
      timestamp: Date.now()
    };

    setToasts(prev => {
      // Keep up to 5 visible toasts at most
      const filtered = prev.filter(t => t.id !== id);
      return [...filtered.slice(-4), newItem];
    });

    if (duration > 0) {
      setTimeout(() => {
        dismiss(id);
      }, duration);
    }

    return id;
  }, [dismiss]);

  const error = useCallback((msg: string, opts?: ToastOptions) => showToast('error', msg, opts), [showToast]);
  const success = useCallback((msg: string, opts?: ToastOptions) => showToast('success', msg, opts), [showToast]);
  const warning = useCallback((msg: string, opts?: ToastOptions) => showToast('warning', msg, opts), [showToast]);
  const info = useCallback((msg: string, opts?: ToastOptions) => showToast('info', msg, opts), [showToast]);

  useEffect(() => {
    globalToastBridge = showToast;
    return () => {
      globalToastBridge = null;
    };
  }, [showToast]);

  // Global browser error listeners to intercept unhandled promise rejections and script errors
  useEffect(() => {
    const handleError = (event: ErrorEvent) => {
      const msg = event?.message || 'Erro inesperado na aplicação';
      if (msg.includes('ResizeObserver') || msg.includes('WebSocket')) return;

      const now = Date.now();
      if (lastErrorRef.current.msg === msg && now - lastErrorRef.current.time < 3000) {
        return; // debounce identical error spam
      }
      lastErrorRef.current = { msg, time: now };

      const details = event.filename ? `${event.filename}:${event.lineno}:${event.colno}` : undefined;
      error(msg, {
        title: 'Exceção Capturada',
        details,
        duration: 8000
      });
    };

    const handleRejection = (event: PromiseRejectionEvent) => {
      let msg = 'Falha em operação assíncrona';
      let details: string | undefined;

      if (event?.reason) {
        if (event.reason instanceof Error) {
          msg = event.reason.message || msg;
          details = event.reason.stack;
        } else if (typeof event.reason === 'string') {
          msg = event.reason;
        } else {
          try {
            details = JSON.stringify(event.reason);
          } catch {
            // ignore
          }
        }
      }

      const now = Date.now();
      if (lastErrorRef.current.msg === msg && now - lastErrorRef.current.time < 3000) {
        return;
      }
      lastErrorRef.current = { msg, time: now };

      error(msg, {
        title: 'Falha de Execução / Rede',
        details,
        duration: 8000
      });
    };

    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleRejection);

    return () => {
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleRejection);
    };
  }, [error]);

  return (
    <ToastContext.Provider value={{ toasts, showToast, error, success, warning, info, dismiss, clearAll }}>
      {children}
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextValue => {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    return {
      toasts: [],
      showToast: () => '',
      error: () => '',
      success: () => '',
      warning: () => '',
      info: () => '',
      dismiss: () => {},
      clearAll: () => {}
    };
  }
  return ctx;
};
