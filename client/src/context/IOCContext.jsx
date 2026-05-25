// ============================================================
// context/IOCContext.jsx — GLOBAL IOC STATE
// ============================================================
// Manages the IOC list, search results, and dashboard stats
// globally so they're accessible from any component.
//
// What it provides:
//   iocs          → paginated list of IOCs
//   stats         → dashboard statistics
//   searchResult  → last enrichment result
//   searchIOC()   → submit an indicator for enrichment
//   fetchIOCs()   → load/refresh IOC list
//   fetchStats()  → load dashboard stats
//   isSearching   → true while enrichment is in progress
//   error         → last error message
// ============================================================

import { createContext, useState, useCallback, useRef } from 'react';
import api from '../api/axios';

export const IOCContext = createContext(null);

export const IOCProvider = ({ children }) => {
  const [iocs,         setIOCs]         = useState([]);
  const [stats,        setStats]        = useState(null);
  const [searchResult, setSearchResult] = useState(null);
  const [pagination,   setPagination]   = useState(null);
  const [isSearching,  setIsSearching]  = useState(false);
  const [isFetching,   setIsFetching]   = useState(false);
  const [error,        setError]        = useState(null);

  // Abort controller ref — cancels in-flight requests on unmount
  const abortRef = useRef(null);

  // ── Search / Enrich a Single IOC ──────────────────────────
  // This is the main action — user types an IP/domain/URL/hash
  // and hits search. We send to backend which calls all the APIs.
  const searchIOC = useCallback(async (indicator) => {
    if (!indicator.trim()) return;

    // Cancel previous in-flight search
    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();

    setIsSearching(true);
    setError(null);
    setSearchResult(null);

    try {
      const response = await api.post('/ioc/search',
        { indicator: indicator.trim() },
        { signal: abortRef.current.signal }
      );

      setSearchResult(response.data.data);
      return response.data.data;

    } catch (err) {
      if (err.name === 'AbortError' || err.name === 'CanceledError') return;
      const msg = err.userMessage || 'Search failed. Please try again.';
      setError(msg);
      throw err;
    } finally {
      setIsSearching(false);
    }
  }, []);

  // ── Fetch Paginated IOC List ───────────────────────────────
  const fetchIOCs = useCallback(async (params = {}) => {
    setIsFetching(true);
    setError(null);

    try {
      const response = await api.get('/ioc', { params });
      setIOCs(response.data.data.iocs);
      setPagination(response.data.data.pagination);
    } catch (err) {
      setError(err.userMessage || 'Failed to load IOCs');
    } finally {
      setIsFetching(false);
    }
  }, []);

  // ── Fetch Dashboard Stats ──────────────────────────────────
  const fetchStats = useCallback(async () => {
    try {
      const response = await api.get('/ioc/stats');
      setStats(response.data.data);
    } catch (err) {
      console.error('Failed to fetch stats:', err.userMessage);
    }
  }, []);

  // ── Flag an IOC as False Positive ─────────────────────────
  const flagFP = useCallback(async (iocId) => {
    try {
      const response = await api.patch(`/ioc/${iocId}/flag`);
      // Update local state without re-fetching
      setIOCs(prev => prev.map(ioc =>
        ioc._id === iocId ? { ...ioc, isFP: !ioc.isFP } : ioc
      ));
      return response.data;
    } catch (err) {
      setError(err.userMessage || 'Failed to flag IOC');
    }
  }, []);

  // ── Delete an IOC ─────────────────────────────────────────
  const deleteIOC = useCallback(async (iocId) => {
    try {
      await api.delete(`/ioc/${iocId}`);
      setIOCs(prev => prev.filter(ioc => ioc._id !== iocId));
    } catch (err) {
      setError(err.userMessage || 'Failed to delete IOC');
    }
  }, []);

  // ── Clear Search Result ────────────────────────────────────
  const clearSearch = useCallback(() => {
    setSearchResult(null);
    setError(null);
  }, []);

  const value = {
    iocs,
    stats,
    searchResult,
    pagination,
    isSearching,
    isFetching,
    error,
    searchIOC,
    fetchIOCs,
    fetchStats,
    flagFP,
    deleteIOC,
    clearSearch,
  };

  return (
    <IOCContext.Provider value={value}>
      {children}
    </IOCContext.Provider>
  );
};
