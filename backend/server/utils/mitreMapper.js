// ============================================================
// utils/mitreMapper.js — MITRE ATT&CK TECHNIQUE MAPPER
// ============================================================
// Maps IOC characteristics to MITRE ATT&CK techniques.
// MITRE ATT&CK is a globally-accessible knowledge base of
// adversary tactics and techniques used in cyberattacks.
//
// Why map to MITRE?
//   - Gives analysts attack context (WHAT is the attacker doing?)
//   - Enables correlation across incidents
//   - Feeds into threat intelligence reports
//   - Required by many compliance frameworks (NIST, SOC2)
//
// Mapping logic:
//   1. Check OTX pulse tags for explicit MITRE IDs (T1566, etc.)
//   2. Infer techniques from IOC characteristics:
//      - Phishing URL → T1566 (Phishing)
//      - C2 IP → T1071 (Application Layer Protocol)
//      - Malware hash → T1204 (User Execution)
//      - High port-scan abuse → T1046 (Network Service Scanning)
// ============================================================

// ── MITRE Technique Reference ──────────────────────────────
// Subset of commonly observed techniques in threat intel
const MITRE_TECHNIQUES = {
  'T1566':     { name: 'Phishing',                         tactic: 'Initial Access',             killChainStage: 'Delivery' },
  'T1566.001': { name: 'Spearphishing Attachment',         tactic: 'Initial Access',             killChainStage: 'Delivery' },
  'T1566.002': { name: 'Spearphishing Link',               tactic: 'Initial Access',             killChainStage: 'Delivery' },
  'T1071':     { name: 'Application Layer Protocol',       tactic: 'Command and Control',        killChainStage: 'Command and Control' },
  'T1071.001': { name: 'Web Protocols',                    tactic: 'Command and Control',        killChainStage: 'Command and Control' },
  'T1071.004': { name: 'DNS',                              tactic: 'Command and Control',        killChainStage: 'Command and Control' },
  'T1046':     { name: 'Network Service Scanning',         tactic: 'Discovery',                  killChainStage: 'Exploitation' },
  'T1110':     { name: 'Brute Force',                      tactic: 'Credential Access',          killChainStage: 'Exploitation' },
  'T1110.001': { name: 'Password Guessing',                tactic: 'Credential Access',          killChainStage: 'Exploitation' },
  'T1204':     { name: 'User Execution',                   tactic: 'Execution',                  killChainStage: 'Installation' },
  'T1204.002': { name: 'Malicious File',                   tactic: 'Execution',                  killChainStage: 'Installation' },
  'T1041':     { name: 'Exfiltration Over C2 Channel',     tactic: 'Exfiltration',               killChainStage: 'Actions on Objectives' },
  'T1048':     { name: 'Exfiltration Over Alt Protocol',   tactic: 'Exfiltration',               killChainStage: 'Actions on Objectives' },
  'T1078':     { name: 'Valid Accounts',                   tactic: 'Defense Evasion',            killChainStage: 'Installation' },
  'T1059':     { name: 'Command and Scripting Interpreter',tactic: 'Execution',                  killChainStage: 'Installation' },
  'T1055':     { name: 'Process Injection',                tactic: 'Defense Evasion',            killChainStage: 'Installation' },
  'T1027':     { name: 'Obfuscated Files or Information',  tactic: 'Defense Evasion',            killChainStage: 'Installation' },
  'T1190':     { name: 'Exploit Public-Facing Application',tactic: 'Initial Access',             killChainStage: 'Exploitation' },
  'T1133':     { name: 'External Remote Services',         tactic: 'Initial Access',             killChainStage: 'Delivery' },
  'T1486':     { name: 'Data Encrypted for Impact',        tactic: 'Impact',                     killChainStage: 'Actions on Objectives' }, // Ransomware
  'T1036':     { name: 'Masquerading',                     tactic: 'Defense Evasion',            killChainStage: 'Installation' },
};

// ── Main Mapping Function ──────────────────────────────────
// Returns array of { techniqueId, techniqueName, tactic, killChainStage }
const mapToMitre = (iocType, enrichmentData, indicator) => {
  const techniques = new Map(); // Use Map to avoid duplicates

  const addTechnique = (id) => {
    if (MITRE_TECHNIQUES[id] && !techniques.has(id)) {
      techniques.set(id, {
        techniqueId:   id,
        techniqueName: MITRE_TECHNIQUES[id].name,
        tactic:        MITRE_TECHNIQUES[id].tactic,
        killChainStage:MITRE_TECHNIQUES[id].killChainStage,
      });
    }
  };

  // ── Step 1: Extract explicit MITRE IDs from OTX ──────────
  // OTX researchers sometimes tag pulses with MITRE IDs directly
  const otxTechniques = enrichmentData.otx?.mitreTechniques || [];
  otxTechniques.forEach(id => addTechnique(id));

  // Also scan OTX pulse tags
  const otxTags = enrichmentData.otx?.tags || [];
  const mitreRegex = /^T\d{4}(\.\d{3})?$/;
  otxTags.forEach(tag => {
    if (mitreRegex.test(tag)) addTechnique(tag);
  });

  // ── Step 2: Infer techniques from IOC characteristics ────

  // ── IP-based inferences ──────────────────────────────────
  if (iocType === 'ip') {
    const abuseScore = enrichmentData.abuseipdb?.abuseConfidenceScore || 0;
    const vtMalicious = enrichmentData.virustotal?.maliciousVotes || 0;
    const recentReports = enrichmentData.abuseipdb?.recentReports || [];

    // High abuse score → likely C2 or scanning
    if (abuseScore >= 50 || vtMalicious >= 5) {
      addTechnique('T1071'); // Application Layer Protocol (C2)
    }

    // Check abuse categories from AbuseIPDB
    // Category 18 = Brute-Force, 14 = Port Scan
    const categories = recentReports.flatMap(r => r.categories || []);
    if (categories.includes(18)) addTechnique('T1110'); // Brute Force
    if (categories.includes(14)) addTechnique('T1046'); // Network Service Scanning

    // Many OTX pulses = known threat infrastructure
    const pulseCount = enrichmentData.otx?.pulseCount || 0;
    if (pulseCount >= 5) {
      addTechnique('T1133'); // External Remote Services
    }
  }

  // ── Domain-based inferences ──────────────────────────────
  if (iocType === 'domain') {
    const vtMalicious = enrichmentData.virustotal?.maliciousVotes || 0;
    const vtCategories = enrichmentData.virustotal?.categories || {};

    // VT category labels contain 'phishing' → phishing technique
    const isPhishing = Object.values(vtCategories)
      .some(cat => cat.toLowerCase().includes('phish'));

    if (isPhishing) {
      addTechnique('T1566.002'); // Spearphishing Link
    } else if (vtMalicious >= 3) {
      addTechnique('T1071.004'); // DNS (C2 via DNS)
    }

    // Newly registered domains often used in attacks
    const creationDate = enrichmentData.virustotal?.creationDate;
    if (creationDate) {
      const ageInDays = (Date.now() - new Date(creationDate)) / (1000 * 60 * 60 * 24);
      if (ageInDays < 30) {
        addTechnique('T1036'); // Masquerading — new domain mimicking legit
      }
    }
  }

  // ── URL-based inferences ──────────────────────────────────
  if (iocType === 'url') {
    const isPhishing = enrichmentData.openphish?.isPhishing;
    const vtMalicious = enrichmentData.virustotal?.maliciousVotes || 0;

    if (isPhishing) {
      addTechnique('T1566.002'); // Spearphishing Link
      addTechnique('T1566');     // Phishing (parent)
    }

    if (vtMalicious >= 3) {
      addTechnique('T1190'); // Exploit Public-Facing Application
    }
  }

  // ── Hash-based inferences ─────────────────────────────────
  if (iocType === 'hash') {
    const vtMalicious = enrichmentData.virustotal?.maliciousVotes || 0;
    const malwareFamilies = enrichmentData.virustotal?.malwareFamilies || [];

    if (vtMalicious >= 10) {
      addTechnique('T1204.002'); // Malicious File
      addTechnique('T1204');     // User Execution (parent)
    }

    // Ransomware family names
    const ransomwareFamilies = ['wannacry', 'ryuk', 'lockbit', 'conti', 'revil', 'blackcat'];
    const isRansomware = malwareFamilies
      .some(f => ransomwareFamilies.some(r => f.toLowerCase().includes(r)));

    if (isRansomware) {
      addTechnique('T1486'); // Data Encrypted for Impact
    }

    if (malwareFamilies.length > 0) {
      addTechnique('T1027'); // Obfuscated Files (malware often obfuscates)
    }
  }

  return [...techniques.values()];
};

module.exports = { mapToMitre, MITRE_TECHNIQUES };
