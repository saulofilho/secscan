import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LanguageProvider, useLanguage } from './lib/i18nContext';
import './index.css';

const AppContainer: React.FC = () => {
  const { language } = useLanguage();
  return <App key={language} />;
};

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <LanguageProvider>
        <AppContainer />
      </LanguageProvider>
    </ErrorBoundary>
  </StrictMode>,
);

