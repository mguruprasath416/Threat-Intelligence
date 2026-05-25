// ============================================================
// hooks/useAuth.js — AUTH HOOK
// ============================================================
// Convenience wrapper around AuthContext.
// Instead of: const { user } = useContext(AuthContext)
// Just write: const { user } = useAuth()
// ============================================================

import { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used inside <AuthProvider>');
  }
  return context;
};
