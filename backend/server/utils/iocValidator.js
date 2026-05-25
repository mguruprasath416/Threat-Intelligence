// ============================================================
// utils/iocValidator.js — IOC TYPE DETECTION & VALIDATION
// ============================================================
// Two jobs:
//   1. detectIOCType(indicator)  → figures out WHAT it is
//   2. validateIOC(indicator)    → checks if it's well-formed
//
// Why auto-detect instead of making the user specify?
//   Better UX — users can paste anything in the search box.
//   The system figures out the type automatically.
//
// Detection order matters — check most-specific first:
//   Hash   → very specific pattern (hex string of fixed length)
//   IP     → numeric dotted-quad or IPv6
//   URL    → starts with http:// or https://
//   Domain → fallback (anything with a dot)
// ============================================================

// ── Regex Patterns ─────────────────────────────────────────

const PATTERNS = {
  // MD5: 32 hex chars | SHA1: 40 hex chars | SHA256: 64 hex chars
  MD5:    /^[a-fA-F0-9]{32}$/,
  SHA1:   /^[a-fA-F0-9]{40}$/,
  SHA256: /^[a-fA-F0-9]{64}$/,

  // IPv4: four octets 0-255 separated by dots
  IPv4: /^(\d{1,3}\.){3}\d{1,3}$/,

  // IPv6: simplified — groups of hex separated by colons
  IPv6: /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:)*:([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/,

  // URL: must start with http or https
  URL: /^https?:\/\/.+/i,

  // Domain: label.label format, no spaces, valid TLD
  // Allows subdomains (sub.example.com)
  DOMAIN: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,

  // Email: basic format check
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};

// ── Detect IOC Type ────────────────────────────────────────
// Returns: 'ip' | 'domain' | 'url' | 'hash' | 'email' | null
const detectIOCType = (indicator) => {
  if (!indicator || typeof indicator !== 'string') return null;

  const trimmed = indicator.trim();

  // Order matters — most specific first

  // 1. Check for file hashes (very specific hex patterns)
  if (PATTERNS.MD5.test(trimmed))    return 'hash';
  if (PATTERNS.SHA1.test(trimmed))   return 'hash';
  if (PATTERNS.SHA256.test(trimmed)) return 'hash';

  // 2. Check for email (before domain — emails contain @ and domain)
  if (PATTERNS.EMAIL.test(trimmed)) return 'email';

  // 3. Check for URLs (before domain — URLs contain domain + path)
  if (PATTERNS.URL.test(trimmed)) return 'url';

  // 4. Check for IP addresses
  if (PATTERNS.IPv4.test(trimmed) && isValidIPv4(trimmed)) return 'ip';
  if (PATTERNS.IPv6.test(trimmed)) return 'ip';

  // 5. Fallback to domain
  if (PATTERNS.DOMAIN.test(trimmed)) return 'domain';

  return null; // Unknown type
};

// ── Validate Specific IOC Types ────────────────────────────

// IPv4 octet range check (regex alone allows 999.999.999.999)
const isValidIPv4 = (ip) => {
  return ip.split('.').every(octet => {
    const num = parseInt(octet, 10);
    return num >= 0 && num <= 255;
  });
};

// Check if IP is private/reserved (not useful to scan)
const isPrivateIP = (ip) => {
  const privateRanges = [
    /^10\./,                          // 10.0.0.0/8
    /^172\.(1[6-9]|2\d|3[01])\./,   // 172.16.0.0/12
    /^192\.168\./,                    // 192.168.0.0/16
    /^127\./,                         // Loopback
    /^169\.254\./,                    // Link-local
    /^0\./,                           // This network
    /^255\./,                         // Broadcast
  ];
  return privateRanges.some(range => range.test(ip));
};

// Detect hash subtype for VirusTotal endpoint routing
const getHashType = (hash) => {
  const h = hash.trim();
  if (PATTERNS.MD5.test(h))    return 'md5';
  if (PATTERNS.SHA1.test(h))   return 'sha1';
  if (PATTERNS.SHA256.test(h)) return 'sha256';
  return null;
};

// ── Full Validation ────────────────────────────────────────
// Returns { valid: bool, type: string|null, error: string|null }
const validateIOC = (indicator) => {
  if (!indicator || typeof indicator !== 'string') {
    return { valid: false, type: null, error: 'Indicator must be a non-empty string' };
  }

  const trimmed = indicator.trim();

  if (trimmed.length < 2) {
    return { valid: false, type: null, error: 'Indicator too short' };
  }

  if (trimmed.length > 2048) {
    return { valid: false, type: null, error: 'Indicator too long (max 2048 chars)' };
  }

  const type = detectIOCType(trimmed);

  if (!type) {
    return { valid: false, type: null, error: 'Cannot determine IOC type. Submit a valid IP, domain, URL, or hash.' };
  }

  // Extra check: warn about private IPs
  if (type === 'ip' && isPrivateIP(trimmed)) {
    return { valid: false, type: 'ip', error: 'Private/reserved IP addresses cannot be enriched' };
  }

  return { valid: true, type, error: null };
};

module.exports = { detectIOCType, validateIOC, isPrivateIP, getHashType, PATTERNS };
