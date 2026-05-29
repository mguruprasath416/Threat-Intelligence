// ============================================================
// api/axios.js — AXIOS INSTANCE
// ============================================================
// In production: uses VITE_API_URL from environment
// In development: uses localhost:5000
// ============================================================

import axios from 'axios';

// This reads from .env file:
// Development: VITE_API_URL = http://localhost:5000/api
// Production:  VITE_API_URL = https://your-backend.railway.app/api
const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
});

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

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;

    if (status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
    }

    if (status === 403) {
      console.error('Access denied');
    }

    const message =
      error.response?.data?.message ||
      error.message ||
      'Something went wrong';
    error.userMessage = message;

    return Promise.reject(error);
  }
);

export default api;