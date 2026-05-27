// ============================================================
// context/AuthContext.jsx — GLOBAL AUTH STATE
// ============================================================
// Manages login session for the entire app.
//
// Session policy:
//   - On every app load, any stored token is immediately cleared.
//   - Users MUST log in every time they open the app.
//   - Session only lives in memory while the tab is open.
//   - Logging out also clears the backend cookie.
// ============================================================

import { createContext, useState, useEffect, useCallback } from 'react';
import api from '../api/axios';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user,      setUser]      = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  // ── Always start fresh: clear any old session on app load ──
  useEffect(() => {
    // Clear any persisted token so users always go through the login page.
    // Session is only active for the lifetime of the current browser tab.
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setIsLoading(false);
  }, []);

  // ── Login: called after successful register or login ─────
  const login = useCallback((userData, token) => {
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
  }, []);

  // ── Logout: clears everything and redirects ───────────────
  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } catch {
      // ignore errors — logout anyway
    }
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    window.location.href = '/login';
  }, []);

  return (
    <AuthContext.Provider value={{
      user,
      isLoading,
      isAuthenticated: !!user,
      isAdmin:         user?.role === 'admin',
      login,
      logout,
    }}>
      {children}
    </AuthContext.Provider>
  );
};