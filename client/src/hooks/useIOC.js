// ============================================================
// hooks/useIOC.js — IOC HOOK
// ============================================================
// Convenience wrapper around IOCContext.
// Also provides additional derived state and helper functions
// that would be repetitive to compute in every component.
// ============================================================

import { useContext, useMemo } from 'react';
import { IOCContext } from '../context/IOCContext';

export const useIOC = () => {
  const context = useContext(IOCContext);
  if (!context) {
    throw new Error('useIOC must be used inside <IOCProvider>');
  }

  // ── Derived: IOCs grouped by severity ─────────────────────
  // Computed once and memoized — only recalculates when iocs changes
  const iocsBySeverity = useMemo(() => ({
    Critical: context.iocs.filter(i => i.severity === 'Critical'),
    High:     context.iocs.filter(i => i.severity === 'High'),
    Medium:   context.iocs.filter(i => i.severity === 'Medium'),
    Low:      context.iocs.filter(i => i.severity === 'Low'),
  }), [context.iocs]);

  // ── Derived: IOCs grouped by type ─────────────────────────
  const iocsByType = useMemo(() => ({
    ip:     context.iocs.filter(i => i.iocType === 'ip'),
    domain: context.iocs.filter(i => i.iocType === 'domain'),
    url:    context.iocs.filter(i => i.iocType === 'url'),
    hash:   context.iocs.filter(i => i.iocType === 'hash'),
  }), [context.iocs]);

  return {
    ...context,
    iocsBySeverity,
    iocsByType,
  };
};
