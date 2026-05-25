// ============================================================
// api/vtApi.js — VIRUSTOTAL API CALLS (via backend)
// ============================================================
// These functions call OUR backend endpoints, which in turn
// call the VirusTotal API. We never call VT directly from
// the browser — that would expose the API key.
//
// The main IOC search endpoint triggers VT enrichment
// automatically. These are supplementary utility calls.
// ============================================================

import api from './axios';

// Trigger a fresh enrichment for a specific IOC
export const refreshVTData = async (iocId) => {
  const response = await api.post(`/ioc/${iocId}/refresh`, { source: 'virustotal' });
  return response.data;
};
