// ============================================================
// services/otxService.js — ALIENVAULT OTX API INTEGRATION
// ============================================================
// AlienVault OTX (Open Threat Exchange) is a community threat
// intelligence platform where security researchers share IOC
// "pulses" — collections of related threat indicators.
//
// What it provides:
//   - Threat pulses mentioning this indicator
//   - MITRE ATT&CK technique mappings
//   - Threat actor associations
//   - Geolocation and passive DNS data
//   - Related malware families
//
// OTX is particularly valuable for:
//   - Understanding threat context (what campaign is this from?)
//   - Finding related indicators (pivot investigations)
//   - MITRE ATT&CK mapping
// ============================================================

const axios  = require('axios');
const { otx } = require('../config/apiKeys');
const logger = require('../utils/logger');

const otxClient = axios.create({
  baseURL: otx.baseUrl,
  headers: {
    'X-OTX-API-KEY': otx.apiKey,
    'Accept':        'application/json',
  },
  timeout: 15000,
});

// ── Get IP Threat Data ─────────────────────────────────────
// OTX organizes data into "sections" — we fetch multiple sections
const getIPData = async (ip) => {
  try {
    // Fetch general info and geo data in parallel for speed
    const [generalRes, geoRes, malwareRes, urlsRes] = await Promise.allSettled([
      otxClient.get(`/indicators/IPv4/${ip}/general`),
      otxClient.get(`/indicators/IPv4/${ip}/geo`),
      otxClient.get(`/indicators/IPv4/${ip}/malware`),
      otxClient.get(`/indicators/IPv4/${ip}/url_list`),
    ]);

    // Extract successful results (some sections may 404)
    const general = generalRes.status === 'fulfilled' ? generalRes.value.data : {};
    const geo     = geoRes.status     === 'fulfilled' ? geoRes.value.data     : {};
    const malware = malwareRes.status === 'fulfilled' ? malwareRes.value.data : {};
    const urls    = urlsRes.status    === 'fulfilled' ? urlsRes.value.data    : {};

    return {
      // Number of OTX pulses (threat reports) mentioning this IP
      pulseCount:    general.pulse_info?.count || 0,
      // Array of pulse titles — gives threat context
      pulses:        general.pulse_info?.pulses?.map(p => ({
        id:          p.id,
        name:        p.name,
        tlp:         p.TLP,           // Traffic Light Protocol: red/amber/green
        tags:        p.tags,
        created:     p.created,
        author:      p.author_name,
        description: p.description,
      })) || [],
      // Tags aggregated from all pulses
      tags:          general.tags || [],
      // Country data from OTX geo section
      country:       geo.country_name  || null,
      countryCode:   geo.country_code  || null,
      city:          geo.city          || null,
      latitude:      geo.latitude      || null,
      longitude:     geo.longitude     || null,
      asn:           geo.asn           || null,
      // Malware hashes seen communicating with this IP
      malwareSamples: malware.data?.slice(0, 20).map(m => m.hash) || [],
      // URLs hosted on this IP
      associatedUrls: urls.url_list?.slice(0, 20).map(u => u.url) || [],
    };

  } catch (err) {
    logger.error(`OTX getIPData error for ${ip}: ${err.message}`);
    return null;
  }
};

// ── Get Domain Threat Data ─────────────────────────────────
const getDomainData = async (domain) => {
  try {
    const [generalRes, malwareRes, urlsRes, passiveDnsRes] = await Promise.allSettled([
      otxClient.get(`/indicators/domain/${domain}/general`),
      otxClient.get(`/indicators/domain/${domain}/malware`),
      otxClient.get(`/indicators/domain/${domain}/url_list`),
      otxClient.get(`/indicators/domain/${domain}/passive_dns`), // Historical DNS
    ]);

    const general    = generalRes.status    === 'fulfilled' ? generalRes.value.data    : {};
    const malware    = malwareRes.status    === 'fulfilled' ? malwareRes.value.data    : {};
    const urls       = urlsRes.status       === 'fulfilled' ? urlsRes.value.data       : {};
    const passiveDns = passiveDnsRes.status === 'fulfilled' ? passiveDnsRes.value.data : {};

    return {
      pulseCount:  general.pulse_info?.count || 0,
      pulses:      general.pulse_info?.pulses?.map(p => ({
        id:   p.id,
        name: p.name,
        tags: p.tags,
      })) || [],
      tags:        general.tags || [],
      // Passive DNS: historical IP addresses this domain resolved to
      // Useful for pivot — find other domains on same infrastructure
      passiveDns:  passiveDns.passive_dns?.slice(0, 20).map(r => ({
        address:  r.address,
        hostname: r.hostname,
        first:    r.first,
        last:     r.last,
      })) || [],
      malwareSamples: malware.data?.slice(0, 20).map(m => m.hash) || [],
      associatedUrls: urls.url_list?.slice(0, 20).map(u => u.url) || [],
    };

  } catch (err) {
    logger.error(`OTX getDomainData error for ${domain}: ${err.message}`);
    return null;
  }
};

// ── Get Hash Threat Data ───────────────────────────────────
const getHashData = async (hash) => {
  try {
    const response = await otxClient.get(`/indicators/file/${hash}/general`);
    const data = response.data;

    return {
      pulseCount: data.pulse_info?.count || 0,
      pulses:     data.pulse_info?.pulses?.map(p => ({
        id:   p.id,
        name: p.name,
        tags: p.tags,
      })) || [],
      // MITRE ATT&CK techniques from OTX pulse tags
      mitreTechniques: extractMitreTechniques(data.pulse_info?.pulses || []),
    };

  } catch (err) {
    logger.error(`OTX getHashData error for ${hash}: ${err.message}`);
    return null;
  }
};

// ── Helper: Extract MITRE Techniques ──────────────────────
// OTX pulses sometimes include MITRE technique IDs in their tags
// Format: 'T1566', 'T1071.001', etc.
const extractMitreTechniques = (pulses) => {
  const mitreRegex = /^T\d{4}(\.\d{3})?$/;
  const techniques = new Set();

  pulses.forEach(pulse => {
    (pulse.tags || []).forEach(tag => {
      if (mitreRegex.test(tag)) {
        techniques.add(tag);
      }
    });
  });

  return [...techniques];
};

module.exports = { getIPData, getDomainData, getHashData };
