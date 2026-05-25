// ============================================================
// vite.config.js — VITE BUILD CONFIGURATION
// ============================================================
// Vite is the build tool / dev server for this React app.
//
// Key config:
//   plugins: [react()] → enables JSX transform + HMR
//   server.proxy       → proxies /api/* to backend in dev
//                        so CORS is avoided during development
//   build.outDir       → where production files go
// ============================================================

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173, // React dev server port

    // Proxy /api requests to Express backend during development
    // This way the browser only talks to localhost:5173
    // and Vite forwards API calls to localhost:5000
    proxy: {
      '/api': {
        target:      'http://localhost:5000',
        changeOrigin: true,
        secure:       false,
      },
    },
  },

  build: {
    outDir:   'dist',
    sourcemap: false, // Disable in production for security
    rollupOptions: {
      output: {
        // Split large dependencies into separate chunks
        // for better browser caching
        manualChunks: {
          react:    ['react', 'react-dom'],
          router:   ['react-router-dom'],
          charts:   ['recharts'],
          axios:    ['axios'],
        },
      },
    },
  },
});
