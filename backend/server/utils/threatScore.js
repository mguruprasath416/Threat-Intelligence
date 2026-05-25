// ============================================================
// utils/threatScore.js — THREAT SCORE CALCULATOR
// ============================================================
// Converts raw API data from multiple sources into a single
// numeric threat score between 0 and 100.
//
// Why a unified score?
//   Each API returns different metrics:
//     VT:       "45 of 92 engines flagged this"
//     AbuseIPDB: "abuseConfidenceScore: 87"
//     OTX:       "pulseCount: 23"
//   A unified score lets us sort, filter, and compare IOCs
//   from different types on the same scale.
//
// Scoring methodology (weighted average):
//   IP:     VT(40%) + AbuseIPDB(40%) + OTX(20%)
//   Domain: VT(60%) + OTX(40%)
//   URL:    VT(70%) + OpenPhish(30%)
//   Hash:   VT(80%) + OTX(20%)
//
// All component scores are normalized to 0-100 before weighting.
// ============================================================

const logger = require('./logger');

// ── Main Scoring Function ──────────────────────────────────
// iocType: 'ip' | 'domain' | 'url' | 'hash'
// enrichmentData: { virustotal, abuseipdb, otx, openphish }
const calculateThreatScore = (iocType, enrichmentData) => {
  try {
    switch (iocType) {
      case 'ip':     return scoreIP(enrichmentData);
      case 'domain': return scoreDomain(enrichmentData);
      case 'url':    return scoreURL(enrichmentData);
      case 'hash':   return scoreHash(enrichmentData);
      default:       return 0;
    }
  } catch (err) {
    logger.error(`Threat scoring error: ${err.message}`);
    return 0;
  }
};

// ── IP Scoring ─────────────────────────────────────────────
const scoreIP = ({ virustotal, abuseipdb, otx }) => {
  let scores = [];

  // VirusTotal component (weight: 40%)
  if (virustotal) {
    const vtScore = normalizeVTScore(virustotal);
    scores.push({ score: vtScore, weight: 0.40 });
  }

  // AbuseIPDB component (weight: 40%)
  // abuseConfidenceScore is already 0-100 — no normalization needed
  if (abuseipdb) {
    const abuseScore = abuseipdb.abuseConfidenceScore || 0;
    scores.push({ score: abuseScore, weight: 0.40 });
  }

  // OTX component (weight: 20%)
  if (otx) {
    const otxScore = normalizeOTXScore(otx);
    scores.push({ score: otxScore, weight: 0.20 });
  }

  return computeWeightedScore(scores);
};

// ── Domain Scoring ─────────────────────────────────────────
const scoreDomain = ({ virustotal, otx }) => {
  let scores = [];

  if (virustotal) {
    scores.push({ score: normalizeVTScore(virustotal), weight: 0.60 });
  }
  if (otx) {
    scores.push({ score: normalizeOTXScore(otx), weight: 0.40 });
  }

  return computeWeightedScore(scores);
};

// ── URL Scoring ────────────────────────────────────────────
const scoreURL = ({ virustotal, openphish }) => {
  let scores = [];

  if (virustotal) {
    scores.push({ score: normalizeVTScore(virustotal), weight: 0.70 });
  }

  if (openphish) {
    // OpenPhish is binary: in the feed = 100, not in feed = 0
    const phishScore = openphish.isPhishing ? 100 : 0;
    scores.push({ score: phishScore, weight: 0.30 });
  }

  return computeWeightedScore(scores);
};

// ── Hash Scoring ───────────────────────────────────────────
const scoreHash = ({ virustotal, otx }) => {
  let scores = [];

  if (virustotal) {
    scores.push({ score: normalizeVTScore(virustotal), weight: 0.80 });
  }
  if (otx) {
    scores.push({ score: normalizeOTXScore(otx), weight: 0.20 });
  }

  return computeWeightedScore(scores);
};

// ── VirusTotal Normalization ───────────────────────────────
// VT returns: { maliciousVotes, suspiciousVotes, harmlessVotes, undetectedVotes }
// We calculate what % of total votes are malicious/suspicious
const normalizeVTScore = (vt) => {
  if (!vt) return 0;

  const malicious   = vt.maliciousVotes   || 0;
  const suspicious  = vt.suspiciousVotes  || 0;
  const harmless    = vt.harmlessVotes    || 0;
  const undetected  = vt.undetectedVotes  || 0;

  const total = malicious + suspicious + harmless + undetected;
  if (total === 0) return 0;

  // Malicious = full weight, suspicious = half weight
  const weightedBad = malicious + (suspicious * 0.5);
  const ratio       = (weightedBad / total) * 100;

  return Math.min(100, Math.round(ratio));
};

// ── OTX Normalization ──────────────────────────────────────
// OTX uses pulse count (0 to potentially thousands)
// Use logarithmic scaling to avoid a single high-count IOC
// dominating the score
const normalizeOTXScore = (otx) => {
  if (!otx || !otx.pulseCount) return 0;

  const pulseCount = otx.pulseCount;

  // log scale: 0→0, 1→20, 5→40, 10→50, 50→70, 100→80, 500→95
  if (pulseCount === 0)   return 0;
  if (pulseCount <= 1)    return 20;
  if (pulseCount <= 5)    return 40;
  if (pulseCount <= 10)   return 50;
  if (pulseCount <= 25)   return 60;
  if (pulseCount <= 50)   return 70;
  if (pulseCount <= 100)  return 80;
  if (pulseCount <= 500)  return 90;
  return 95;
};

// ── Weighted Average ───────────────────────────────────────
// scores: [{ score: 0-100, weight: 0-1 }, ...]
// Adjusts weights if some APIs returned no data
const computeWeightedScore = (scores) => {
  if (scores.length === 0) return 0;

  // Normalize weights to sum to 1.0
  const totalWeight = scores.reduce((sum, s) => sum + s.weight, 0);
  if (totalWeight === 0) return 0;

  const weightedSum = scores.reduce((sum, s) => {
    const normalizedWeight = s.weight / totalWeight;
    return sum + (s.score * normalizedWeight);
  }, 0);

  return Math.min(100, Math.max(0, Math.round(weightedSum)));
};

module.exports = { calculateThreatScore };
