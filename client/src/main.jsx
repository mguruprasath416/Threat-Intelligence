// ============================================================
// main.jsx — VITE ENTRY POINT
// ============================================================
// This is the very first JS file Vite loads.
// It mounts the React app onto the #root div in index.html.
//
// StrictMode: In development, renders components twice to
// detect side effects. Has no effect in production.
// ============================================================

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
);
