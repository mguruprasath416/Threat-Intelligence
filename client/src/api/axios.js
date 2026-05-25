// ============================================================
// api/axios.js — CONFIGURED AXIOS INSTANCE
// ============================================================
// Creates a pre-configured Axios instance shared across all
// API modules. Handles:
//   - Base URL from environment variable
//   - Automatic JWT attachment on every request
//   - Automatic 401 handling (redirect to login on token expiry)
//   - Consistent error formatting
//
// Every API call in the app uses this instance — not raw axios.
// That way auth logic lives in ONE place, not in every component.
// ============================================================

import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api',
  timeout: 30000, // 30 seconds — enrichment can be slow
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true, // Send cookies (for httpOnly cookie auth)
});

// ── Request Interceptor ────────────────────────────────────
// Runs BEFORE every request is sent
// Attaches JWT from localStorage to Authorization header
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response Interceptor ───────────────────────────────────
// Runs AFTER every response is received
// Handles global error cases (401, 403, 500)
api.interceptors.response.use(
  (response) => response, // Pass successful responses through unchanged

  (error) => {
    const status = error.response?.status;

    // 401 = token expired or invalid → force logout
    if (status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      // Redirect to login without React Router (works from anywhere)
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }

    // 403 = authenticated but not authorized → show error
    if (status === 403) {
      console.error('Access denied — insufficient permissions');
    }

    // Normalize error message: use server's message if available
    const message = error.response?.data?.message || error.message || 'Something went wrong';
    error.userMessage = message; // Attach for easy access in components

    return Promise.reject(error);
  }
);

export default api;
