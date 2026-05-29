// ============================================================
// vite.config.js — VITE CONFIG FOR RAILWAY DEPLOYMENT
// ============================================================

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },

  // Railway uses $PORT environment variable
  // preview serves the built files in production
  preview: {
    port:  process.env.PORT ? parseInt(process.env.PORT) : 4173,
    host:  '0.0.0.0',   // Must be 0.0.0.0 for Railway
    allowedHosts: 'all', // Allow Railway domain
  },

  build: {
    outDir:    'dist',
    sourcemap: false,
  },
});