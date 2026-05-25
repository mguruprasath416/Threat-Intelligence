// ============================================================
// jobs/fetchThreatFeeds.js — SCHEDULED FEED FETCHER
// ============================================================
// This job runs on a schedule (using node-cron) to automatically
// pull the latest IOCs from OpenPhish and other feeds.
//
// Without this job:
//   The system only learns about IOCs when analysts search them.
//
// With this job:
//   The system proactively collects threats and populates the
//   ThreatFeed page automatically — analysts see threats without
//   having to search for them individually.
//
// Schedule: Every 6 hours
//   cron format: '0 */6 * * *'
//   minute(0) hour(every 6) day(*) month(*) weekday(*)
// ============================================================

const cron             = require('node-cron');
const openphishService = require('../services/openphishService');
const IOC              = require('../models/IOC');
const logger           = require('../utils/logger');

// ── Main Job: Fetch OpenPhish Feed ─────────────────────────
const fetchOpenPhishFeed = async () => {
  logger.info('🔄 Scheduled job: Fetching OpenPhish feed...');

  try {
    // Refresh the in-memory cache
    await openphishService.refreshFeed();

    // Get recent phishing URLs from the refreshed cache
    const phishingURLs = await openphishService.getRecentPhishingURLs(100);

    if (!phishingURLs || phishingURLs.length === 0) {
      logger.warn('OpenPhish feed returned no URLs');
      return;
    }

    let newCount     = 0;
    let updatedCount = 0;

    // Upsert each URL into the IOC collection
    // bulkWrite is much faster than individual save() calls
    const bulkOps = phishingURLs.map(urlData => ({
      updateOne: {
        filter: { indicator: urlData.url, iocType: 'url' },
        update: {
          $set: {
            indicator:    urlData.url,
            iocType:      'url',
            severity:     'High',
            threatScore:  75, // OpenPhish confirmed = high confidence
            source:       'openphish',
            tags:         ['phishing', 'openphish', 'url'],
            isActive:     true,
            lastEnriched: new Date(),
            // Mark as phishing in enrichment data
            'enrichment.openphish': {
              isPhishing: true,
              matchType:  'feed',
              feedDate:   urlData.timestamp,
            },
          },
          // $setOnInsert only runs on INSERT (new document)
          $setOnInsert: {
            createdAt:   new Date(),
            submittedBy: null,
          },
        },
        upsert: true, // Create if not exists
      },
    }));

    if (bulkOps.length > 0) {
      const result = await IOC.bulkWrite(bulkOps, { ordered: false });
      newCount     = result.upsertedCount;
      updatedCount = result.modifiedCount;
    }

    logger.info(`✅ OpenPhish job complete: ${newCount} new, ${updatedCount} updated IOCs`);

  } catch (err) {
    logger.error(`OpenPhish fetch job failed: ${err.message}`);
  }
};

// ── Start All Scheduled Jobs ───────────────────────────────
const startJobs = () => {

  // Fetch OpenPhish every 6 hours
  cron.schedule('0 */6 * * *', fetchOpenPhishFeed, {
    scheduled: true,
    timezone:  'UTC',
  });

  // Run immediately on startup (don't wait 6 hours for first data)
  fetchOpenPhishFeed();

  logger.info('📅 Scheduled jobs started:');
  logger.info('   - OpenPhish feed: every 6 hours');
};

module.exports = { startJobs, fetchOpenPhishFeed };


// ============================================================
// jobs/cleanupOldIOCs.js — SCHEDULED CLEANUP JOB
// ============================================================
// Removes or archives IOCs that are stale (not seen recently).
// Keeps the database lean and query performance high.
//
// Why clean up?
//   - Dynamic IPs rotate — an IP flagged 6 months ago may now
//     be assigned to a legitimate user
//   - Old phishing URLs are taken down — no point alerting on them
//   - Keeps storage costs manageable
//
// Schedule: Daily at 2 AM UTC
// ============================================================

const cleanupOldIOCs = async () => {
  logger.info('🧹 Scheduled job: Cleaning up old IOCs...');

  try {
    const STALE_THRESHOLD_DAYS = parseInt(process.env.IOC_STALE_DAYS || '90');
    const cutoffDate = new Date(
      Date.now() - STALE_THRESHOLD_DAYS * 24 * 60 * 60 * 1000
    );

    // Soft-delete IOCs from automated feeds that are older than threshold
    // Keep manually submitted IOCs (submittedBy != null) regardless of age
    const result = await IOC.updateMany(
      {
        source:      { $in: ['openphish', 'api_enrichment'] },
        submittedBy: null,        // Auto-fetched (not manually submitted)
        createdAt:   { $lt: cutoffDate },
        isActive:    true,
      },
      {
        $set: { isActive: false }
      }
    );

    logger.info(`✅ Cleanup complete: ${result.modifiedCount} stale IOCs archived`);

  } catch (err) {
    logger.error(`IOC cleanup job failed: ${err.message}`);
  }
};

// Export cleanup so it can be started separately if needed
module.exports.cleanupOldIOCs = cleanupOldIOCs;
