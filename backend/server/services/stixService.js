// ============================================================
// services/stixService.js — STIX 2.1 CONVERSION SERVICE
// ============================================================
// Converts IOC MongoDB documents into STIX 2.1 compliant objects.
//
// STIX 2.1 spec references used:
//   - indicator SDO: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v
//   - bundle:        https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_gms872kuzdmg
//   - STIX Patterning Language for indicator.pattern
//
// IOC type → STIX pattern mapping:
//   ip      → [ipv4-addr:value = '<IP>']
//   domain  → [domain-name:value = '<domain>']
//   url     → [url:value = '<url>']
//   hash    → [file:hashes.'SHA-256' = '<hash>'] (auto-detects MD5/SHA-1/SHA-256)
//   email   → [email-message:from_ref.value = '<email>']
//
// Severity → STIX confidence score:
//   Critical → 90  High → 70  Medium → 40  Low → 15
// ============================================================

const { v4: uuidv4 } = require('uuid');

// ── Constants ────────────────────────────────────────────────

// Static identity SDO representing this platform as the STIX producer
const PLATFORM_IDENTITY = {
  type:        'identity',
  spec_version: '2.1',
  id:          'identity--ioc-sentinel-platform',
  name:        'IOC Sentinel',
  identity_class: 'system',
  description: 'Threat Intelligence Platform — IOC Sentinel',
  created:     '2024-01-01T00:00:00.000Z',
  modified:    '2024-01-01T00:00:00.000Z',
};

// TAXII Collection definitions (static — extend as needed)
const TAXII_COLLECTIONS = [
  {
    id:          'ioc-sentinel-all',
    title:       'IOC Sentinel — All Indicators',
    description: 'All active IOC indicators enriched by the IOC Sentinel platform.',
    can_read:    true,
    can_write:   false,
    media_types: ['application/stix+json;version=2.1'],
  },
  {
    id:          'ioc-sentinel-critical',
    title:       'IOC Sentinel — Critical & High',
    description: 'Critical and High severity IOCs only.',
    can_read:    true,
    can_write:   false,
    media_types: ['application/stix+json;version=2.1'],
  },
];

// Map IOC severity → STIX confidence integer (0–100)
const SEVERITY_TO_CONFIDENCE = {
  Critical: 90,
  High:     70,
  Medium:   40,
  Low:      15,
};

// Map IOC severity → STIX indicator labels (open vocab)
const SEVERITY_TO_LABELS = {
  Critical: ['malicious-activity', 'attribution'],
  High:     ['malicious-activity'],
  Medium:   ['anomalous-activity'],
  Low:      ['benign'],
};

// ── Pattern builders ─────────────────────────────────────────

/**
 * Detect hash type by string length.
 * MD5 = 32 chars, SHA-1 = 40, SHA-256 = 64, SHA-512 = 128
 */
const detectHashType = (hash) => {
  const h = hash.trim();
  if (h.length === 32)  return 'MD5';
  if (h.length === 40)  return 'SHA-1';
  if (h.length === 64)  return 'SHA-256';
  if (h.length === 128) return 'SHA-512';
  return 'SHA-256'; // default fallback
};

/**
 * Build a valid STIX 2.1 pattern string from an IOC document.
 * Returns null if the type is unrecognised.
 */
const buildStixPattern = (ioc) => {
  const val = ioc.indicator.trim();

  switch (ioc.iocType) {
    case 'ip':
      // Supports IPv4. IPv6 would use ipv6-addr:value
      return `[ipv4-addr:value = '${val}']`;

    case 'domain':
      return `[domain-name:value = '${val}']`;

    case 'url':
      // Escape single quotes inside URL values
      return `[url:value = '${val.replace(/'/g, "\\'")}']`;

    case 'hash': {
      const hashType = detectHashType(val);
      return `[file:hashes.'${hashType}' = '${val}']`;
    }

    case 'email':
      return `[email-addr:value = '${val}']`;

    default:
      return null;
  }
};

/**
 * Map IOC type to STIX pattern_type (always 'stix' for our patterns).
 * Could be 'snort', 'yara', etc. for other pattern types.
 */
const buildPatternType = () => 'stix';

/**
 * Build STIX kill_chain_phases from MITRE ATT&CK technique data.
 * Uses the MITRE ATT&CK kill chain name.
 */
const buildKillChainPhases = (mitreTechniques = []) => {
  if (!mitreTechniques.length) return undefined;

  const seen = new Set();
  const phases = [];

  mitreTechniques.forEach(({ tactic, killChainStage }) => {
    const phase = (tactic || killChainStage || '').toLowerCase().replace(/\s+/g, '-');
    if (phase && !seen.has(phase)) {
      seen.add(phase);
      phases.push({
        kill_chain_name: 'mitre-attack',
        phase_name:      phase,
      });
    }
  });

  return phases.length ? phases : undefined;
};

/**
 * Build the external_references array for a STIX indicator.
 * Includes VirusTotal / AbuseIPDB links when available.
 */
const buildExternalRefs = (ioc) => {
  const refs = [];

  // VirusTotal reference
  if (ioc.enrichment?.virustotal) {
    let url;
    switch (ioc.iocType) {
      case 'ip':     url = `https://www.virustotal.com/gui/ip-address/${ioc.indicator}`; break;
      case 'domain': url = `https://www.virustotal.com/gui/domain/${ioc.indicator}`; break;
      case 'url':    url = `https://www.virustotal.com/gui/url/${Buffer.from(ioc.indicator).toString('base64url')}`; break;
      case 'hash':   url = `https://www.virustotal.com/gui/file/${ioc.indicator}`; break;
      default: break;
    }
    if (url) {
      refs.push({
        source_name:  'VirusTotal',
        url,
        description:  `VirusTotal analysis for ${ioc.indicator}`,
      });
    }
  }

  // AbuseIPDB reference (IPs only)
  if (ioc.enrichment?.abuseipdb && ioc.iocType === 'ip') {
    refs.push({
      source_name:  'AbuseIPDB',
      url:          `https://www.abuseipdb.com/check/${ioc.indicator}`,
      description:  `AbuseIPDB report for ${ioc.indicator}`,
    });
  }

  // MITRE ATT&CK references for mapped techniques
  (ioc.mitreTechniques || []).forEach(({ techniqueId, techniqueName }) => {
    if (techniqueId) {
      refs.push({
        source_name:    'mitre-attack',
        url:            `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}`,
        external_id:    techniqueId,
        description:    techniqueName || techniqueId,
      });
    }
  });

  return refs.length ? refs : undefined;
};

// ── Core converter ───────────────────────────────────────────

/**
 * Convert a single IOC Mongoose document to a STIX 2.1 Indicator SDO.
 * Returns null if no valid pattern can be built (shouldn't happen with valid IOC types).
 *
 * STIX Indicator SDO required fields:
 *   type, spec_version, id, created, modified, name,
 *   indicator_types, pattern, pattern_type, valid_from
 */
const iocToStixIndicator = (ioc) => {
  const pattern = buildStixPattern(ioc);
  if (!pattern) return null;

  const created  = ioc.createdAt  ? new Date(ioc.createdAt).toISOString()  : new Date().toISOString();
  const modified = ioc.updatedAt  ? new Date(ioc.updatedAt).toISOString()  : created;

  // STIX ID must be a UUID URN prefixed with type name
  const stixId = `indicator--${ioc._id.toString().padStart(36, '0').slice(-36)}`;

  const killChainPhases = buildKillChainPhases(ioc.mitreTechniques);
  const externalRefs    = buildExternalRefs(ioc);
  const labels          = SEVERITY_TO_LABELS[ioc.severity] || SEVERITY_TO_LABELS.Low;
  const confidence      = SEVERITY_TO_CONFIDENCE[ioc.severity] ?? 15;

  const indicator = {
    type:             'indicator',
    spec_version:     '2.1',
    id:               stixId,
    created_by_ref:   PLATFORM_IDENTITY.id,
    created:          created,
    modified:         modified,
    revoked:          ioc.isFP || false,    // false positive = revoked

    // Human-readable name
    name: `${ioc.iocType.toUpperCase()}: ${ioc.indicator}`,

    // Optional description combining source + tags
    description: [
      ioc.source ? `Source: ${ioc.source}` : null,
      ioc.tags?.length ? `Tags: ${ioc.tags.join(', ')}` : null,
      ioc.geoLocation?.country ? `Country: ${ioc.geoLocation.country}` : null,
      ioc.geoLocation?.isp     ? `ISP: ${ioc.geoLocation.isp}`         : null,
    ].filter(Boolean).join(' | ') || undefined,

    // Open vocabulary indicator types (STIX 2.1 §10.9)
    indicator_types: labels,

    // The actual pattern (STIX patterning language)
    pattern:      pattern,
    pattern_type: buildPatternType(),

    // When this indicator was first valid (use IOC creation date)
    valid_from: created,

    // Threat score → confidence (STIX confidence is 0–100)
    confidence,

    // Severity as a custom extension field (x_ prefix = custom in STIX)
    x_ioc_severity:    ioc.severity    || 'Low',
    x_ioc_threat_score: ioc.threatScore ?? 0,
    x_ioc_type:        ioc.iocType,

    // Labels used for filtering in TAXII consumers
    labels,
  };

  // Only add optional fields if they have values (STIX must not have null props)
  if (killChainPhases) indicator.kill_chain_phases = killChainPhases;
  if (externalRefs)    indicator.external_references = externalRefs;

  // Add granular marking (TLP:AMBER) as object_marking_refs
  indicator.object_marking_refs = ['marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'];

  return indicator;
};

// ── Bundle builder ───────────────────────────────────────────

/**
 * Wrap an array of STIX objects into a STIX 2.1 Bundle.
 *
 * Bundle SDO spec:
 *   type:    'bundle'
 *   id:      'bundle--<uuid>'
 *   objects: [ ...STIX SDOs/SROs/SCOs ]
 *
 * Always injects:
 *   - TLP:AMBER marking definition
 *   - Platform identity SDO
 */
const buildStixBundle = (iocDocs, options = {}) => {
  const {
    collectionId  = 'ioc-sentinel-all',
    includeRevoked = false,
  } = options;

  // TLP:AMBER marking definition (STIX 2.1 standard marking)
  const tlpAmber = {
    type:             'marking-definition',
    spec_version:     '2.1',
    id:               'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    created:          '2017-01-20T00:00:00.000Z',
    definition_type:  'tlp',
    definition: { tlp: 'amber' },
  };

  // Convert each IOC → STIX indicator (filter out nulls and revoked unless requested)
  const indicators = iocDocs
    .map(iocToStixIndicator)
    .filter((obj) => {
      if (!obj) return false;
      if (!includeRevoked && obj.revoked) return false;
      return true;
    });

  return {
    type:         'bundle',
    id:           `bundle--${uuidv4()}`,
    spec_version: '2.1',
    // Bundle metadata (non-standard but widely consumed by TAXII clients)
    _collection_id: collectionId,
    _exported_at:   new Date().toISOString(),
    _total_count:   indicators.length,
    objects: [
      tlpAmber,
      PLATFORM_IDENTITY,
      ...indicators,
    ],
  };
};

// ── Collection filter helpers ────────────────────────────────

/**
 * Apply TAXII collection filtering rules.
 * 'ioc-sentinel-critical' → only Critical + High severity IOCs
 */
const filterByCollection = (iocDocs, collectionId) => {
  if (collectionId === 'ioc-sentinel-critical') {
    return iocDocs.filter(i => ['Critical', 'High'].includes(i.severity));
  }
  // Default collection returns all active IOCs
  return iocDocs.filter(i => i.isActive && !i.isFP);
};

// ── Public API ───────────────────────────────────────────────

module.exports = {
  iocToStixIndicator,
  buildStixBundle,
  filterByCollection,
  TAXII_COLLECTIONS,
  PLATFORM_IDENTITY,
};
