// ============================================================
// services/virustotalService.js — VIRUSTOTAL API INTEGRATION
// ============================================================
// VirusTotal scans indicators against 70+ antivirus engines
// and security vendors and returns reputation data.
//
// What it tells us:
//   - How many AV engines flagged this as malicious
//   - Categories (malware, phishing, spam, etc.)
//   - Country of origin (for IPs)
//   - SSL certificate info (for domains)
//   - File metadata (for hashes)
//
// Endpoints used:
//   /ip_addresses/{ip}       → IP reputation
//   /domains/{domain}        → Domain reputation
//   /urls (POST then GET)    → URL scan (2-step process)
//   /files/{hash}            → File hash lookup
// ============================================================

const axios   = require('axios');
const { virustotal } = require('../config/apiKeys');
const logger  = require('../utils/logger');

// Axios instance pre-configured with VT base URL and API key header
const vtClient = axios.create({
  baseURL: virustotal.baseUrl,
  headers: {
    'x-apikey': virustotal.apiKey,
    'Accept':   'application/json',
  },
  timeout: 15000, // 15 second timeout
});

// ── Enrich IP Address ──────────────────────────────────────
// Returns: malicious/suspicious vote counts, country, ASN, ISP
const enrichIP = async (ip) => {
  try {
    const response = await vtClient.get(`/ip_addresses/${ip}`);
    const attrs = response.data.data.attributes;

    return {
      maliciousVotes:   attrs.last_analysis_stats?.malicious    || 0,
      suspiciousVotes:  attrs.last_analysis_stats?.suspicious   || 0,
      harmlessVotes:    attrs.last_analysis_stats?.harmless     || 0,
      undetectedVotes:  attrs.last_analysis_stats?.undetected   || 0,
      country:          attrs.country                            || null,
      asOwner:          attrs.as_owner                          || null,
      asn:              attrs.asn                               || null,
      reputation:       attrs.reputation                        || 0,
      // Last time any engine analysed this IP
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000) // Unix → JS Date
        : null,
      // Individual engine results: { engine_name: { category, result } }
      engineResults:    attrs.last_analysis_results             || {},
      rawData:          attrs, // Store full response for deep dives
    };

  } catch (err) {
    // 404 = VT has never seen this IP — not necessarily safe, just unknown
    if (err.response?.status === 404) {
      logger.warn(`VT: IP ${ip} not found in database`);
      return null;
    }
    logger.error(`VT enrichIP error for ${ip}: ${err.message}`);
    throw err;
  }
};

// ── Enrich Domain ─────────────────────────────────────────
const enrichDomain = async (domain) => {
  try {
    const response = await vtClient.get(`/domains/${domain}`);
    const attrs = response.data.data.attributes;

    return {
      maliciousVotes:   attrs.last_analysis_stats?.malicious   || 0,
      suspiciousVotes:  attrs.last_analysis_stats?.suspicious  || 0,
      harmlessVotes:    attrs.last_analysis_stats?.harmless    || 0,
      reputation:       attrs.reputation                       || 0,
      categories:       attrs.categories                       || {}, // { vendor: category }
      registrar:        attrs.registrar                        || null,
      creationDate:     attrs.creation_date
        ? new Date(attrs.creation_date * 1000)
        : null,
      // DNS records for pivot investigations
      lastDnsRecords:   attrs.last_dns_records                 || [],
      lastHttpsCert:    attrs.last_https_certificate           || null,
      rawData:          attrs,
    };

  } catch (err) {
    if (err.response?.status === 404) {
      logger.warn(`VT: Domain ${domain} not found`);
      return null;
    }
    logger.error(`VT enrichDomain error for ${domain}: ${err.message}`);
    throw err;
  }
};

// ── Enrich URL ────────────────────────────────────────────
// URLs require a 2-step process:
//   Step 1: Submit URL for scanning → get scan ID
//   Step 2: Fetch results using scan ID
const enrichURL = async (url) => {
  try {
    // Step 1: Submit URL — VT queues it for scanning
    const submitRes = await vtClient.post('/urls',
      new URLSearchParams({ url }), // must be form-encoded
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // The scan ID is used to fetch results
    const analysisId = submitRes.data.data.id;

    // Step 2: Fetch scan results (wait 2 seconds for processing)
    await new Promise(r => setTimeout(r, 2000));
    const resultRes = await vtClient.get(`/analyses/${analysisId}`);
    const attrs = resultRes.data.data.attributes;

    return {
      maliciousVotes:  attrs.stats?.malicious   || 0,
      suspiciousVotes: attrs.stats?.suspicious  || 0,
      harmlessVotes:   attrs.stats?.harmless    || 0,
      status:          attrs.status,             // 'completed' | 'queued' | 'in-progress'
      engineResults:   attrs.results            || {},
      rawData:         attrs,
    };

  } catch (err) {
    logger.error(`VT enrichURL error for ${url}: ${err.message}`);
    throw err;
  }
};

// ── Enrich File Hash ──────────────────────────────────────
// Supports MD5, SHA1, SHA256
const enrichHash = async (hash) => {
  try {
    const response = await vtClient.get(`/files/${hash}`);
    const attrs = response.data.data.attributes;

    return {
      maliciousVotes:  attrs.last_analysis_stats?.malicious   || 0,
      suspiciousVotes: attrs.last_analysis_stats?.suspicious  || 0,
      harmlessVotes:   attrs.last_analysis_stats?.harmless    || 0,
      // File metadata
      fileName:        attrs.meaningful_name                  || null,
      fileType:        attrs.type_description                 || null,
      fileSize:        attrs.size                             || null,
      md5:             attrs.md5                              || null,
      sha1:            attrs.sha1                             || null,
      sha256:          attrs.sha256                           || null,
      // Malware family names identified by engines
      malwareFamilies: attrs.popular_threat_classification?.popular_threat_name || [],
      engineResults:   attrs.last_analysis_results           || {},
      rawData:         attrs,
    };

  } catch (err) {
    if (err.response?.status === 404) {
      logger.warn(`VT: Hash ${hash} not found`);
      return null;
    }
    logger.error(`VT enrichHash error for ${hash}: ${err.message}`);
    throw err;
  }
};

module.exports = { enrichIP, enrichDomain, enrichURL, enrichHash };
