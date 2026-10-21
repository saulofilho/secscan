import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LanguageProvider } from './lib/i18nContext';
import { ToastProvider } from './lib/toastContext';
import { Toaster } from './components/Toaster';
import './index.css';

const AppContainer: React.FC = () => {
  return (
    <>
      <App />
      <Toaster />
    </>
  );
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <LanguageProvider>
        <ToastProvider>
          <AppContainer />
        </ToastProvider>
      </LanguageProvider>
    </ErrorBoundary>
  </StrictMode>,
);

