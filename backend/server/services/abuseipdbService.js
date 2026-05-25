// ============================================================
// services/abuseipdbService.js — ABUSEIPDB API INTEGRATION
// ============================================================
// AbuseIPDB is a crowdsourced IP abuse database.
// Community members report IPs involved in:
//   - SSH brute force attacks
//   - Port scanning
//   - DDoS attacks
//   - Web spam
//   - Hacking attempts
//
// Key metric: "abuseConfidenceScore" (0-100)
//   0   = no reports (likely clean)
//   100 = universally reported as abusive
//
// Only works for IP addresses (not domains/URLs/hashes)
// ============================================================

const axios  = require('axios');
const { abuseipdb } = require('../config/apiKeys');
const logger = require('../utils/logger');

const abuseClient = axios.create({
  baseURL: abuseipdb.baseUrl,
  headers: {
    'Key':    abuseipdb.apiKey,
    'Accept': 'application/json',
  },
  timeout: 10000,
});

// ── Check IP Reputation ────────────────────────────────────
// maxAgeInDays: only count reports from the last N days
// (older reports may be less relevant for dynamic IPs)
const checkIP = async (ip, maxAgeInDays = 90) => {
  try {
    const response = await abuseClient.get('/check', {
      params: {
        ipAddress:    ip,
        maxAgeInDays: maxAgeInDays,
        verbose:      true, // Include individual report details
      }
    });

    const data = response.data.data;

    return {
      ipAddress:            data.ipAddress,
      // The key score — this is what feeds into our threat scoring
      abuseConfidenceScore: data.abuseConfidenceScore || 0,
      totalReports:         data.totalReports         || 0,
      numDistinctUsers:     data.numDistinctUsers     || 0, // How many different people reported
      countryCode:          data.countryCode          || null,
      countryName:          data.countryName          || null,
      isp:                  data.isp                  || null,
      domain:               data.domain               || null,
      // Is this IP hosting TOR exit node?
      isTorNode:            data.isTor                || false,
      usageType:            data.usageType            || null, // 'Data Center/Web Hosting/Transit', etc.
      lastReportedAt:       data.lastReportedAt       || null,
      // Recent abuse categories reported (see AbuseIPDB category list)
      // 18=Brute-Force, 14=Port Scan, 4=DDoS Attack, 21=Web App Attack
      recentReports:        data.reports?.slice(0, 10) || [], // Last 10 reports
      rawData:              data,
    };

  } catch (err) {
    if (err.response?.status === 422) {
      // 422 = invalid IP format (private IPs like 192.168.x.x are rejected)
      logger.warn(`AbuseIPDB: Invalid or private IP ${ip}`);
      return null;
    }
    logger.error(`AbuseIPDB checkIP error for ${ip}: ${err.message}`);
    throw err;
  }
};

// ── Report a Malicious IP ─────────────────────────────────
// Analysts can contribute back to the community
// categories: array of category IDs (see AbuseIPDB docs)
const reportIP = async (ip, categories, comment) => {
  try {
    const response = await abuseClient.post('/report', {
      ip,
      categories: categories.join(','),
      comment,
    });

    logger.info(`AbuseIPDB: Successfully reported IP ${ip}`);
    return response.data.data;

  } catch (err) {
    logger.error(`AbuseIPDB reportIP error for ${ip}: ${err.message}`);
    throw err;
  }
};

module.exports = { checkIP, reportIP };
