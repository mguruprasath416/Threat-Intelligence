// ============================================================
// services/enrichmentService.js — ENRICHMENT ORCHESTRATOR
// ============================================================
// This is the BRAIN of the backend.
// It decides which APIs to call based on IOC type,
// runs them in parallel, merges results, calculates threat
// score, maps MITRE techniques, and returns a unified object.
//
// Flow for a single IOC:
//   1. Detect IOC type (ip / domain / url / hash)
//   2. Call relevant APIs in parallel (Promise.allSettled)
//   3. Merge all API results into one enrichment object
//   4. Calculate threat score (0-100)
//   5. Map to MITRE ATT&CK techniques
//   6. Return complete enriched IOC
//
// Why Promise.allSettled instead of Promise.all?
//   allSettled waits for ALL promises and collects results
//   even if some fail. Promise.all would abort everything
//   if one API is down — we don't want that.
// ============================================================

const vtService       = require('./virustotalService');
const abuseService    = require('./abuseipdbService');
const otxService      = require('./otxService');
const openphishService = require('./openphishService');
const { calculateThreatScore } = require('../utils/threatScore');
const { mapToMitre }           = require('../utils/mitreMapper');
const { detectIOCType }        = require('../utils/iocValidator');
const logger                   = require('../utils/logger');

// ── Main Enrichment Function ───────────────────────────────
// Called by iocController when a user searches or submits an IOC
const enrichIOC = async (indicator) => {
  logger.info(`Enrichment started for: ${indicator}`);

  // Step 1: Auto-detect what type this indicator is
  const iocType = detectIOCType(indicator);
  if (!iocType) {
    throw new Error(`Cannot detect IOC type for: ${indicator}`);
  }

  logger.info(`Detected type: ${iocType}`);

  // Step 2: Route to the right enrichment pipeline
  let enrichmentData = {};

  switch (iocType) {
    case 'ip':
      enrichmentData = await enrichIPAddress(indicator);
      break;
    case 'domain':
      enrichmentData = await enrichDomain(indicator);
      break;
    case 'url':
      enrichmentData = await enrichURL(indicator);
      break;
    case 'hash':
      enrichmentData = await enrichHash(indicator);
      break;
    default:
      throw new Error(`Unsupported IOC type: ${iocType}`);
  }

  // Step 3: Calculate unified threat score from all API data
  const threatScore = calculateThreatScore(iocType, enrichmentData);

  // Step 4: Determine severity band from score
  const severity = getSeverityFromScore(threatScore);

  // Step 5: Map to MITRE ATT&CK techniques
  const mitreTechniques = mapToMitre(iocType, enrichmentData, indicator);

  // Step 6: Extract geolocation if available
  const geoLocation = extractGeoLocation(enrichmentData);

  // Step 7: Collect tags from all sources
  const tags = collectTags(iocType, enrichmentData);

  logger.info(`Enrichment complete for ${indicator}: score=${threatScore}, severity=${severity}`);

  return {
    indicator,
    iocType,
    severity,
    threatScore,
    enrichment:     enrichmentData,
    mitreTechniques,
    geoLocation,
    tags,
    lastEnriched:   new Date(),
    source:         'api_enrichment',
  };
};

// ── IP Address Enrichment Pipeline ────────────────────────
// Calls: VirusTotal + AbuseIPDB + OTX (all in parallel)
const enrichIPAddress = async (ip) => {
  const [vtResult, abuseResult, otxResult] = await Promise.allSettled([
    vtService.enrichIP(ip),
    abuseService.checkIP(ip),
    otxService.getIPData(ip),
  ]);

  return {
    virustotal: vtResult.status    === 'fulfilled' ? vtResult.value    : null,
    abuseipdb:  abuseResult.status === 'fulfilled' ? abuseResult.value : null,
    otx:        otxResult.status   === 'fulfilled' ? otxResult.value   : null,
    // Log failures but don't crash — partial data is better than nothing
    errors: [
      vtResult.status    === 'rejected' ? { source: 'virustotal', error: vtResult.reason.message }    : null,
      abuseResult.status === 'rejected' ? { source: 'abuseipdb',  error: abuseResult.reason.message } : null,
      otxResult.status   === 'rejected' ? { source: 'otx',        error: otxResult.reason.message }   : null,
    ].filter(Boolean),
  };
};

// ── Domain Enrichment Pipeline ────────────────────────────
// Calls: VirusTotal + OTX (AbuseIPDB doesn't support domains)
const enrichDomain = async (domain) => {
  const [vtResult, otxResult] = await Promise.allSettled([
    vtService.enrichDomain(domain),
    otxService.getDomainData(domain),
  ]);

  return {
    virustotal: vtResult.status  === 'fulfilled' ? vtResult.value  : null,
    abuseipdb:  null, // AbuseIPDB is IP-only
    otx:        otxResult.status === 'fulfilled' ? otxResult.value : null,
    errors: [
      vtResult.status  === 'rejected' ? { source: 'virustotal', error: vtResult.reason.message }  : null,
      otxResult.status === 'rejected' ? { source: 'otx',        error: otxResult.reason.message } : null,
    ].filter(Boolean),
  };
};

// ── URL Enrichment Pipeline ───────────────────────────────
// Calls: VirusTotal + OpenPhish (OTX for URLs is limited)
const enrichURL = async (url) => {
  const [vtResult, phishResult] = await Promise.allSettled([
    vtService.enrichURL(url),
    openphishService.isPhishingURL(url),
  ]);

  return {
    virustotal:  vtResult.status    === 'fulfilled' ? vtResult.value    : null,
    abuseipdb:   null,
    otx:         null,
    openphish:   phishResult.status === 'fulfilled' ? phishResult.value : null,
    errors: [
      vtResult.status    === 'rejected' ? { source: 'virustotal', error: vtResult.reason.message }    : null,
      phishResult.status === 'rejected' ? { source: 'openphish',  error: phishResult.reason.message } : null,
    ].filter(Boolean),
  };
};

// ── Hash Enrichment Pipeline ──────────────────────────────
// Calls: VirusTotal + OTX (both support file hashes)
const enrichHash = async (hash) => {
  const [vtResult, otxResult] = await Promise.allSettled([
    vtService.enrichHash(hash),
    otxService.getHashData(hash),
  ]);

  return {
    virustotal: vtResult.status  === 'fulfilled' ? vtResult.value  : null,
    abuseipdb:  null,
    otx:        otxResult.status === 'fulfilled' ? otxResult.value : null,
    errors: [
      vtResult.status  === 'rejected' ? { source: 'virustotal', error: vtResult.reason.message }  : null,
      otxResult.status === 'rejected' ? { source: 'otx',        error: otxResult.reason.message } : null,
    ].filter(Boolean),
  };
};

// ── Severity Band Mapping ─────────────────────────────────
// Converts numeric score (0-100) to severity label
const getSeverityFromScore = (score) => {
  if (score >= 76) return 'Critical';
  if (score >= 51) return 'High';
  if (score >= 26) return 'Medium';
  return 'Low';
};

// ── Geo Location Extractor ────────────────────────────────
// Pulls geo data from whichever API returned it
const extractGeoLocation = (enrichmentData) => {
  // Try VT first, then AbuseIPDB, then OTX
  if (enrichmentData.virustotal?.country) {
    return {
      countryCode: enrichmentData.virustotal.country,
      asn:         enrichmentData.virustotal.asn,
    };
  }
  if (enrichmentData.abuseipdb?.countryCode) {
    return {
      country:     enrichmentData.abuseipdb.countryName,
      countryCode: enrichmentData.abuseipdb.countryCode,
      isp:         enrichmentData.abuseipdb.isp,
    };
  }
  if (enrichmentData.otx?.country) {
    return {
      country:     enrichmentData.otx.country,
      countryCode: enrichmentData.otx.countryCode,
      city:        enrichmentData.otx.city,
      latitude:    enrichmentData.otx.latitude,
      longitude:   enrichmentData.otx.longitude,
    };
  }
  return {};
};

// ── Tag Collector ─────────────────────────────────────────
// Aggregates tags from all API results into a flat unique list
const collectTags = (iocType, enrichmentData) => {
  const tagSet = new Set([iocType]);

  // Tags from OTX pulses
  if (enrichmentData.otx?.tags) {
    enrichmentData.otx.tags.forEach(t => tagSet.add(t.toLowerCase()));
  }

  // Malware family names from VirusTotal
  if (enrichmentData.virustotal?.malwareFamilies) {
    enrichmentData.virustotal.malwareFamilies.forEach(f => tagSet.add(f.toLowerCase()));
  }

  // OpenPhish confirmed phishing
  if (enrichmentData.openphish?.isPhishing) {
    tagSet.add('phishing');
    tagSet.add('openphish-confirmed');
  }

  // High abuse score → tag as scanner/brute-force
  if (enrichmentData.abuseipdb?.abuseConfidenceScore >= 80) {
    tagSet.add('high-abuse');
  }

  return [...tagSet];
};

module.exports = { enrichIOC };
