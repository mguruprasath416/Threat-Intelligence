// ============================================================
// services/huntService.js — THREAT HUNTING RULE GENERATION
// ============================================================
// Generates hunting rules in various formats (YARA, Sigma, KQL, SPL)
// from selected IOCs for threat hunting across different platforms
// ============================================================

const IOC = require('../models/IOC');
const logger = require('../utils/logger');

// ── YARA Rule Generation ─────────────────────────────────────
// Generates YARA rules for file hash and domain/IP indicators
const generateYARA = (iocs) => {
  const hashes = iocs.filter(i => i.iocType === 'hash');
  const domains = iocs.filter(i => i.iocType === 'domain');
  const ips = iocs.filter(i => i.iocType === 'ip');
  const urls = iocs.filter(i => i.iocType === 'url');

  let rules = [];

  // Generate hash-based YARA rules
  if (hashes.length > 0) {
    const hashConditions = hashes.map(h => `uint16(0) == 0x5A4D and hash.md5(0, filesize) == "${h.indicator}"`).join(' or ');
    
    rules.push(`rule ThreatIntel_Hash_${Date.now()} {
    meta:
        description = "Threat intelligence IOC match from hash indicators"
        author = "Threat Intel Platform"
        date = "${new Date().toISOString().split('T')[0]}"
        ioc_count = ${hashes.length}
    condition:
        ${hashConditions}
}`);
  }

  // Generate domain-based YARA rules
  if (domains.length > 0) {
    const domainStrings = domains.map(d => `$domain_${d.indicator.replace(/[^a-zA-Z0-9]/g, '_')} = "${d.indicator}" nocase`).join('\n    ');
    const domainConditions = domains.map(d => `$domain_${d.indicator.replace(/[^a-zA-Z0-9]/g, '_')}`).join(' or ');

    rules.push(`rule ThreatIntel_Domain_${Date.now()} {
    strings:
        ${domainStrings}
    condition:
        ${domainConditions}
}`);
  }

  // Generate IP-based YARA rules
  if (ips.length > 0) {
    const ipStrings = ips.map(ip => `$ip_${ip.indicator.replace(/\./g, '_')} = "${ip.indicator}" ascii`).join('\n    ');
    const ipConditions = ips.map(ip => `$ip_${ip.indicator.replace(/\./g, '_')}`).join(' or ');

    rules.push(`rule ThreatIntel_IP_${Date.now()} {
    strings:
        ${ipStrings}
    condition:
        ${ipConditions}
}`);
  }

  // Generate URL-based YARA rules
  if (urls.length > 0) {
    const urlStrings = urls.map(u => `$url_${u.indicator.replace(/[^a-zA-Z0-9]/g, '_')} = "${u.indicator}" nocase`).join('\n    ');
    const urlConditions = urls.map(u => `$url_${u.indicator.replace(/[^a-zA-Z0-9]/g, '_')}`).join(' or ');

    rules.push(`rule ThreatIntel_URL_${Date.now()} {
    strings:
        ${urlStrings}
    condition:
        ${urlConditions}
}`);
  }

  return rules.join('\n\n');
};

// ── Sigma Rule Generation ─────────────────────────────────────
// Generates Sigma rules for SIEM integration
const generateSigma = (iocs) => {
  const hashes = iocs.filter(i => i.iocType === 'hash');
  const domains = iocs.filter(i => i.iocType === 'domain');
  const ips = iocs.filter(i => i.iocType === 'ip');
  const urls = iocs.filter(i => i.iocType === 'url');

  let detection = {};

  // Hash detection
  if (hashes.length > 0) {
    detection.hash = {
      'selection': {
        'Hashes|contains': hashes.map(h => h.indicator)
      },
      'condition': 'selection'
    };
  }

  // Domain detection
  if (domains.length > 0) {
    detection.domain = {
      'selection': {
        'DomainName|contains': domains.map(d => d.indicator)
      },
      'condition': 'selection'
    };
  }

  // IP detection
  if (ips.length > 0) {
    detection.ip = {
      'selection': {
        'IpAddress|contains': ips.map(ip => ip.indicator)
      },
      'condition': 'selection'
    };
  }

  // URL detection
  if (urls.length > 0) {
    detection.url = {
      'selection': {
        'Url|contains': urls.map(u => u.indicator)
      },
      'condition': 'selection'
    };
  }

  const sigmaRule = {
    title: 'Threat Intelligence IOC Match',
    id: `threat_intel_${Date.now()}`,
    description: 'Detection rule generated from threat intelligence IOCs',
    author: 'Threat Intel Platform',
    status: 'stable',
    references: ['Generated from IOC database'],
    tags: ['threat-intel', 'ioc-match'],
    logsource: {
      category: ['network', 'file'],
      product: ['windows', 'linux', 'macos']
    },
    detection: detection,
    level: 'high'
  };

  return JSON.stringify(sigmaRule, null, 2);
};

// ── KQL (Kibana Query Language) Generation ───────────────────
// Generates KQL queries for Elasticsearch/Kibana
const generateKQL = (iocs) => {
  const hashes = iocs.filter(i => i.iocType === 'hash');
  const domains = iocs.filter(i => i.iocType === 'domain');
  const ips = iocs.filter(i => i.iocType === 'ip');
  const urls = iocs.filter(i => i.iocType === 'url');

  let queries = [];

  if (hashes.length > 0) {
    const hashQuery = hashes.map(h => `hash: "${h.indicator}"`).join(' OR ');
    queries.push(`// Hash Match\n${hashQuery}`);
  }

  if (domains.length > 0) {
    const domainQuery = domains.map(d => `domain: "${d.indicator}"`).join(' OR ');
    queries.push(`// Domain Match\n${domainQuery}`);
  }

  if (ips.length > 0) {
    const ipQuery = ips.map(ip => `source.ip: "${ip.indicator}" OR destination.ip: "${ip.indicator}"`).join(' OR ');
    queries.push(`// IP Match\n${ipQuery}`);
  }

  if (urls.length > 0) {
    const urlQuery = urls.map(u => `url: "${u.indicator}"`).join(' OR ');
    queries.push(`// URL Match\n${urlQuery}`);
  }

  if (queries.length === 0) {
    return '// No IOCs selected for KQL generation';
  }

  return queries.join('\n\n');
};

// ── SPL (Splunk Search Processing Language) Generation ───────
// Generates SPL queries for Splunk
const generateSPL = (iocs) => {
  const hashes = iocs.filter(i => i.iocType === 'hash');
  const domains = iocs.filter(i => i.iocType === 'domain');
  const ips = iocs.filter(i => i.iocType === 'ip');
  const urls = iocs.filter(i => i.iocType === 'url');

  let queries = [];

  if (hashes.length > 0) {
    const hashQuery = hashes.map(h => `hash="${h.indicator}"`).join(' OR ');
    queries.push(`// Hash Match\nindex=* ${hashQuery}`);
  }

  if (domains.length > 0) {
    const domainQuery = domains.map(d => `domain="${d.indicator}"`).join(' OR ');
    queries.push(`// Domain Match\nindex=* ${domainQuery}`);
  }

  if (ips.length > 0) {
    const ipQuery = ips.map(ip => `(src_ip="${ip.indicator}" OR dest_ip="${ip.indicator}")`).join(' OR ');
    queries.push(`// IP Match\nindex=* ${ipQuery}`);
  }

  if (urls.length > 0) {
    const urlQuery = urls.map(u => `url="${u.indicator}"`).join(' OR ');
    queries.push(`// URL Match\nindex=* ${urlQuery}`);
  }

  if (queries.length === 0) {
    return '// No IOCs selected for SPL generation';
  }

  return queries.join('\n\n');
};

// ── Main Generate Function ───────────────────────────────────
const generateHuntRule = async (iocIds, format) => {
  try {
    // Fetch IOCs by IDs
    const iocs = await IOC.find({ _id: { $in: iocIds } }).lean();

    if (iocs.length === 0) {
      throw new Error('No IOCs found for the provided IDs');
    }

    let rule = '';

    switch (format.toLowerCase()) {
      case 'yara':
        rule = generateYARA(iocs);
        break;
      case 'sigma':
        rule = generateSigma(iocs);
        break;
      case 'kql':
        rule = generateKQL(iocs);
        break;
      case 'spl':
        rule = generateSPL(iocs);
        break;
      default:
        throw new Error(`Unsupported format: ${format}`);
    }

    logger.info(`Generated ${format.toUpperCase()} rule for ${iocs.length} IOCs`);

    return {
      success: true,
      format: format.toUpperCase(),
      iocCount: iocs.length,
      rule: rule
    };

  } catch (err) {
    logger.error(`generateHuntRule error: ${err.message}`);
    throw err;
  }
};

module.exports = {
  generateHuntRule,
  generateYARA,
  generateSigma,
  generateKQL,
  generateSPL
};
