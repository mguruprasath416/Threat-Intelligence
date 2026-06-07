// ============================================================
// POWER BI EXPORT CONTROLLER
// GET /api/ioc/export/powerbi
// ============================================================
// Returns IOC data in a flat JSON format that Power BI
// can directly consume via REST API connector.
//
// Power BI connects to this URL and refreshes data
// on a schedule — giving live threat intelligence visuals.
// ============================================================

const exportForPowerBI = async (req, res, next) => {
  try {
    const db_IOC = require('../models/IOC');

    // Fetch all active IOCs — flattened for Power BI
    const iocs = await db_IOC.find({ isActive: true })
      .sort({ createdAt: -1 })
      .limit(10000) // Power BI handles up to 10k rows well
      .lean();

    // Flatten nested objects into flat columns
    // Power BI needs simple key:value — no nested objects
    const flatData = iocs.map(ioc => ({
      // Core fields
      id:           ioc._id.toString(),
      indicator:    ioc.indicator,
      ioc_type:     ioc.iocType,
      severity:     ioc.severity,
      threat_score: ioc.threatScore || 0,
      source:       ioc.source || 'manual',
      is_fp:        ioc.isFP ? 'Yes' : 'No',

      // Dates
      created_at:    ioc.createdAt
        ? new Date(ioc.createdAt).toISOString().slice(0, 10)
        : null,
      last_enriched: ioc.lastEnriched
        ? new Date(ioc.lastEnriched).toISOString().slice(0, 10)
        : null,

      // Geolocation (for IPs)
      country:      ioc.geoLocation?.country     || 'Unknown',
      country_code: ioc.geoLocation?.countryCode || 'XX',
      city:         ioc.geoLocation?.city        || 'Unknown',
      isp:          ioc.geoLocation?.isp         || 'Unknown',
      asn:          ioc.geoLocation?.asn         || 'Unknown',

      // VirusTotal data
      vt_malicious:  ioc.enrichment?.virustotal?.maliciousVotes  || 0,
      vt_suspicious: ioc.enrichment?.virustotal?.suspiciousVotes || 0,
      vt_harmless:   ioc.enrichment?.virustotal?.harmlessVotes   || 0,
      vt_reputation: ioc.enrichment?.virustotal?.reputation      || 0,

      // AbuseIPDB data
      abuse_score:   ioc.enrichment?.abuseipdb?.abuseConfidenceScore || 0,
      abuse_reports: ioc.enrichment?.abuseipdb?.totalReports         || 0,
      is_tor:        ioc.enrichment?.abuseipdb?.isTorNode
        ? 'Yes' : 'No',

      // OTX data
      otx_pulses:    ioc.enrichment?.otx?.pulseCount || 0,

      // Tags (comma separated for Power BI)
      tags: (ioc.tags || []).join(', '),

      // MITRE techniques (comma separated)
      mitre_techniques: (ioc.mitreTechniques || [])
        .map(t => t.techniqueId).join(', '),
      mitre_tactics: (ioc.mitreTechniques || [])
        .map(t => t.tactic).join(', '),

      // Severity as number for Power BI charts
      severity_number:
        ioc.severity === 'Critical' ? 4 :
        ioc.severity === 'High'     ? 3 :
        ioc.severity === 'Medium'   ? 2 : 1,
    }));

    // Return in Power BI compatible format
    res.status(200).json({
      success:       true,
      total:         flatData.length,
      generated_at:  new Date().toISOString(),
      data:          flatData,
    });

  } catch (err) {
    next(err);
  }
};

// ── STATS EXPORT for Power BI KPI cards ──────────────────
const exportStatsForPowerBI = async (req, res, next) => {
  try {
    const db_IOC = require('../models/IOC');

    const [
      totalIOCs,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      topCountries,
      topTypes,
      dailyTrend,
    ] = await Promise.all([
      db_IOC.countDocuments({ isActive: true }),
      db_IOC.countDocuments({ isActive: true, severity: 'Critical' }),
      db_IOC.countDocuments({ isActive: true, severity: 'High' }),
      db_IOC.countDocuments({ isActive: true, severity: 'Medium' }),
      db_IOC.countDocuments({ isActive: true, severity: 'Low' }),

      db_IOC.aggregate([
        { $match: { isActive: true, 'geoLocation.country': { $ne: null } } },
        { $group: { _id: '$geoLocation.country', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),

      db_IOC.aggregate([
        { $match: { isActive: true } },
        { $group: { _id: '$iocType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),

      db_IOC.aggregate([
        {
          $match: {
            createdAt: {
              $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
            }
          }
        },
        {
          $group: {
            _id: {
              $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } },
      ]),
    ]);

    res.status(200).json({
      success:      true,
      generated_at: new Date().toISOString(),
      kpis: {
        total_iocs:     totalIOCs,
        critical_count: criticalCount,
        high_count:     highCount,
        medium_count:   mediumCount,
        low_count:      lowCount,
        critical_pct:   totalIOCs > 0
          ? ((criticalCount / totalIOCs) * 100).toFixed(1)
          : 0,
      },
      top_countries: topCountries.map(c => ({
        country: c._id,
        count:   c.count,
      })),
      ioc_types: topTypes.map(t => ({
        type:  t._id,
        count: t.count,
      })),
      daily_trend: dailyTrend.map(d => ({
        date:  d._id,
        count: d.count,
      })),
    });

  } catch (err) {
    next(err);
  }
};

module.exports = { exportForPowerBI, exportStatsForPowerBI };