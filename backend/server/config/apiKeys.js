// ============================================================
// config/apiKeys.js — EXTERNAL API KEY CONFIGURATION
// ============================================================
// Centralizes all third-party API keys in one place.
// Keys are loaded from .env — NEVER hardcode keys in source code.
//
// Services used:
//   VirusTotal  — malware/URL/IP reputation (free: 4 req/min)
//   AbuseIPDB   — IP abuse reports database (free: 1000 req/day)
//   AlienVault OTX — open threat exchange feed (free)
//   OpenPhish   — phishing URL feed (free, no key needed)
// ============================================================

module.exports = {
  virustotal: {
    apiKey:  process.env.VT_API_KEY,
    baseUrl: 'https://www.virustotal.com/api/v3',
    // Free tier: 4 lookups/minute, 500/day
    rateLimit: { requests: 4, perMinute: 1 },
  },

  abuseipdb: {
    apiKey:  process.env.ABUSEIPDB_API_KEY,
    baseUrl: 'https://api.abuseipdb.com/api/v2',
    // Free tier: 1000 requests/day
    rateLimit: { requests: 1000, perDay: 1 },
  },

  otx: {
    apiKey:  process.env.OTX_API_KEY,
    baseUrl: 'https://otx.alienvault.com/api/v1',
    // Free with account — generous limits
  },

  openphish: {
    // No API key needed — public feed URL
    feedUrl: 'https://openphish.com/feed.txt',
    // Updated every ~1 hour
    refreshInterval: 60 * 60 * 1000, // 1 hour in ms
  },
};
