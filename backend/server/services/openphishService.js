// ============================================================
// services/openphishService.js — OPENPHISH FEED INTEGRATION
// ============================================================
// OpenPhish is a free, public phishing URL feed.
// It publishes a plain text file of active phishing URLs
// updated approximately every 12 hours.
//
// Unlike VirusTotal/AbuseIPDB (query per IOC), OpenPhish
// works as a bulk feed — we download the full list and cache
// it in memory, then check if a URL exists in that list.
//
// This is much faster and doesn't burn API quota for each check.
//
// Feed URL: https://openphish.com/feed.txt
// Format: one URL per line
// ============================================================

const axios  = require('axios');
const { openphish } = require('../config/apiKeys');
const logger = require('../utils/logger');

// In-memory cache of phishing URLs
// Structure: Set<string> for O(1) lookups
let phishingUrlCache = new Set();
let lastFetchTime    = null;

// ── Fetch and Cache the Feed ──────────────────────────────
// Downloads the full OpenPhish feed and stores it in memory
const refreshFeed = async () => {
  try {
    logger.info('OpenPhish: Refreshing phishing URL feed...');

    const response = await axios.get(openphish.feedUrl, {
      timeout: 30000, // 30s — feed can be large
      responseType: 'text',
    });

    // Parse: split by newline, filter empty lines, trim whitespace
    const urls = response.data
      .split('\n')
      .map(url => url.trim().toLowerCase())
      .filter(url => url.length > 0 && url.startsWith('http'));

    // Replace cache atomically
    phishingUrlCache = new Set(urls);
    lastFetchTime    = new Date();

    logger.info(`OpenPhish: Loaded ${phishingUrlCache.size} phishing URLs`);
    return true;

  } catch (err) {
    logger.error(`OpenPhish feed refresh failed: ${err.message}`);
    return false;
  }
};

// ── Check if URL is Phishing ──────────────────────────────
// Returns true if URL (or its domain) is in the phishing feed
const isPhishingURL = async (url) => {
  // Auto-refresh if cache is empty or older than configured interval
  const needsRefresh = !lastFetchTime ||
    (Date.now() - lastFetchTime.getTime() > openphish.refreshInterval);

  if (needsRefresh) {
    await refreshFeed();
  }

  const normalizedUrl = url.trim().toLowerCase();

  // Exact match check
  if (phishingUrlCache.has(normalizedUrl)) {
    return { isPhishing: true, matchType: 'exact' };
  }

  // Domain-level match — check if the domain of the URL
  // appears in any phishing entry (catches subdomain variations)
  try {
    const urlObj  = new URL(normalizedUrl);
    const domain  = urlObj.hostname;

    for (const phishUrl of phishingUrlCache) {
      try {
        const phishDomain = new URL(phishUrl).hostname;
        if (phishDomain === domain) {
          return { isPhishing: true, matchType: 'domain' };
        }
      } catch {
        continue; // Skip malformed URLs in feed
      }
    }
  } catch {
    // URL parsing failed — can't do domain check
  }

  return { isPhishing: false, matchType: null };
};

// ── Get Recent Phishing URLs ──────────────────────────────
// Returns a slice of the current feed for the ThreatFeed page
const getRecentPhishingURLs = async (limit = 50) => {
  if (!lastFetchTime) {
    await refreshFeed();
  }

  // Convert Set to Array and return a slice
  return [...phishingUrlCache].slice(0, limit).map(url => ({
    url,
    source:    'openphish',
    iocType:   'url',
    severity:  'High',
    timestamp: lastFetchTime,
  }));
};

// ── Feed Stats ────────────────────────────────────────────
const getFeedStats = () => ({
  totalUrls:     phishingUrlCache.size,
  lastRefreshed: lastFetchTime,
  isLoaded:      phishingUrlCache.size > 0,
});

module.exports = { refreshFeed, isPhishingURL, getRecentPhishingURLs, getFeedStats };
