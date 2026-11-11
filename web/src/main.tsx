import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource-variable/red-hat-text/wght.css';
import '@fontsource-variable/red-hat-display/wght.css';
import '@fontsource-variable/red-hat-mono/wght.css';
import './styles/index.css';
import './lib/i18n';
import { applyTheme, readStoredTheme } from './lib/theme';
import { App } from './app/App';

// Set the theme before the first paint (no inline script is allowed by the CSP).
applyTheme(readStoredTheme());

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
