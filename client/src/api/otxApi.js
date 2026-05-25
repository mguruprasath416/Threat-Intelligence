// ============================================================
// api/otxApi.js — OTX API CALLS (via backend)
// ============================================================
import api from './axios';

export const getOTXPulses = async (indicator) => {
  const response = await api.get(`/ioc/otx-pulses?indicator=${encodeURIComponent(indicator)}`);
  return response.data;
};
