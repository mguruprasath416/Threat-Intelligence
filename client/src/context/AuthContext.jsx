// ============================================================
// context/AuthContext.jsx — GLOBAL AUTHENTICATION STATE
// ============================================================
// React Context provides global state without prop drilling.
// This context manages the logged-in user's session.
//
// What it provides to the whole app:
//   user        → current user object (null if not logged in)
//   token       → JWT string
//   login()     → save token + user after successful login
//   logout()    → clear everything, redirect to /login
//   isLoading   → true while checking stored token on startup
//
// Usage in any component:
//   const { user, logout } = useContext(AuthContext);
//   Or use the custom hook: const { user } = useAuth();
// ============================================================

import { createContext, useState, useEffect, useCallback } from 'react';
import api from '../api/axios';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user,      setUser]      = useState(null);
  const [token,     setToken]     = useState(null);
  const [isLoading, setIsLoading] = useState(true); // true until we check localStorage

  // ── Initialize: Restore session from localStorage ─────────
  // On first mount, check if we have a stored token.
  // If yes, verify it's still valid by calling /auth/me
  useEffect(() => {
    const initAuth = async () => {
      const storedToken = localStorage.getItem('token');
      const storedUser  = localStorage.getItem('user');

      if (storedToken && storedUser) {
        try {
          // Verify token is still valid with the server
          const response = await api.get('/auth/me');
          setUser(response.data.data);
          setToken(storedToken);
        } catch {
          // Token expired or invalid — clear storage
          localStorage.removeItem('token');
          localStorage.removeItem('user');
        }
      }

      setIsLoading(false); // Done checking — render the app
    };

    initAuth();
  }, []);

  // ── Login ──────────────────────────────────────────────────
  // Called after successful login API response
  const login = useCallback((userData, jwtToken) => {
    setUser(userData);
    setToken(jwtToken);
    localStorage.setItem('token', jwtToken);
    localStorage.setItem('user', JSON.stringify(userData));
  }, []);

  // ── Logout ────────────────────────────────────────────────
  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout'); // Clear server-side cookie
    } catch { /* ignore errors */ }

    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
  }, []);

  const value = {
    user,
    token,
    isLoading,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin',
    login,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
