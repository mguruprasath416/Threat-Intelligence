// ============================================================
// utils/formatDate.js — DATE FORMATTING UTILITIES
// ============================================================
// Consistent date display across the app.
// ============================================================

export const formatDate = (dateString) => {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
};

export const formatDateTime = (dateString) => {
  if (!dateString) return 'N/A';
  return new Date(dateString).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
};

export const timeAgo = (dateString) => {
  if (!dateString) return 'N/A';
  const seconds = Math.floor((Date.now() - new Date(dateString)) / 1000);
  if (seconds < 60)   return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};


// ============================================================
// utils/severityColor.js — SEVERITY COLOR MAPPING
// ============================================================
// Maps severity strings to CSS variables/classes.
// Single source of truth — change once, updates everywhere.
// ============================================================

export const SEVERITY_COLORS = {
  Low:      { text: '#00ff88', bg: 'rgba(0,255,136,0.12)',  border: 'rgba(0,255,136,0.3)',  class: 'badge-low' },
  Medium:   { text: '#ffcc00', bg: 'rgba(255,204,0,0.12)',  border: 'rgba(255,204,0,0.3)',  class: 'badge-medium' },
  High:     { text: '#ff8800', bg: 'rgba(255,136,0,0.12)',  border: 'rgba(255,136,0,0.3)',  class: 'badge-high' },
  Critical: { text: '#ff3355', bg: 'rgba(255,51,85,0.12)',  border: 'rgba(255,51,85,0.3)',  class: 'badge-critical' },
};

export const getSeverityColor  = (severity) => SEVERITY_COLORS[severity]?.text  || '#7a9bb5';
export const getSeverityBg     = (severity) => SEVERITY_COLORS[severity]?.bg    || 'transparent';
export const getSeverityClass  = (severity) => SEVERITY_COLORS[severity]?.class || '';

export const IOC_TYPE_COLORS = {
  ip:     '#00d4ff',
  domain: '#7c6af7',
  url:    '#ff8800',
  hash:   '#00ff88',
  email:  '#ff3355',
};

export const getTypeColor = (type) => IOC_TYPE_COLORS[type] || '#7a9bb5';


// ============================================================
// utils/validateIOC.js — CLIENT-SIDE IOC VALIDATION
// ============================================================
// Mirrors the server-side validation for instant feedback.
// Prevents unnecessary API calls for clearly invalid inputs.
// ============================================================

const PATTERNS = {
  MD5:    /^[a-fA-F0-9]{32}$/,
  SHA1:   /^[a-fA-F0-9]{40}$/,
  SHA256: /^[a-fA-F0-9]{64}$/,
  IPv4:   /^(\d{1,3}\.){3}\d{1,3}$/,
  URL:    /^https?:\/\/.+/i,
  DOMAIN: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  EMAIL:  /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};

export const detectType = (indicator) => {
  const v = indicator.trim();
  if (PATTERNS.MD5.test(v) || PATTERNS.SHA1.test(v) || PATTERNS.SHA256.test(v)) return 'hash';
  if (PATTERNS.EMAIL.test(v)) return 'email';
  if (PATTERNS.URL.test(v))   return 'url';
  if (PATTERNS.IPv4.test(v))  return 'ip';
  if (PATTERNS.DOMAIN.test(v)) return 'domain';
  return null;
};

export const validateIndicator = (indicator) => {
  if (!indicator?.trim()) return { valid: false, error: 'Please enter an indicator' };
  const type = detectType(indicator);
  if (!type) return { valid: false, error: 'Invalid format. Enter an IP, domain, URL, or hash.' };
  return { valid: true, type, error: null };
};
