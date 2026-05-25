// ============================================================
// api/abuseipdbApi.js
// ============================================================
import api from './axios';
export const getAbuseReport = async (ip) => {
  const response = await api.get(`/ioc/abuse-check?ip=${encodeURIComponent(ip)}`);
  return response.data;
};
