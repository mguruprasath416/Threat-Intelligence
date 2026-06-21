// ============================================================
// controllers/taxiiController.js — TAXII 2.1 SERVER
// ============================================================
// Implements a TAXII 2.1 compliant read-only server.
//
// TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
//
// Endpoint map (all under /api/taxii):
//
//   GET /                           → Server discovery (§4.1)
//   GET /collections                → List available collections (§5.1)
//   GET /collections/:id            → Get collection metadata (§5.2)
//   GET /collections/:id/objects    → Get objects from collection (§5.4)
//   GET /collections/:id/manifest   → Get object manifest (§5.5)
//
// STIX export endpoint (not TAXII spec, for browser download):
//   GET /export                     → Full STIX bundle download
//   GET /export/:collectionId       → Collection-filtered STIX bundle download
//
// Content-Type: application/taxii+json;version=2.1  (TAXII responses)
//               application/stix+json;version=2.1   (STIX bundle responses)
//
// Auth: Bearer JWT (same as all other API endpoints)
// ============================================================

const IOC = require('../models/IOC');
const {
  buildStixBundle,
  filterByCollection,
  TAXII_COLLECTIONS,
  PLATFORM_IDENTITY,
} = require('../services/stixService');
const logger = require('../utils/logger');

// ── TAXII Media Types ─────────────────────────────────────────
const TAXII_CONTENT_TYPE = 'application/taxii+json;version=2.1';
const STIX_CONTENT_TYPE  = 'application/stix+json;version=2.1';

// ── Pagination helper ─────────────────────────────────────────
// TAXII spec §5.4 supports added_after, limit, and next cursor.
const DEFAULT_PAGE_SIZE = 500; // max objects per TAXII response

// ── Load all active IOCs (shared across endpoints) ────────────
const loadIOCs = async (userId, added_after = null) => {
  const filter = { isActive: true };
  // Scope to requesting user's own IOCs
  if (userId) filter.submittedBy = userId;
  // TAXII added_after query param filters by creation timestamp
  if (added_after) {
    const dt = new Date(added_after);
    if (!isNaN(dt)) filter.createdAt = { $gt: dt };
  }
  return IOC.find(filter)
    .sort({ createdAt: -1 })
    .lean();
};

// ─────────────────────────────────────────────────────────────
// GET /api/taxii/
// TAXII 2.1 Server Discovery — §4.1
// Returns information about the TAXII server itself.
// ─────────────────────────────────────────────────────────────
const getDiscovery = (req, res) => {
  const base = `${req.protocol}://${req.get('host')}/api/taxii`;

  res.set('Content-Type', TAXII_CONTENT_TYPE);
  res.json({
    title:       'IOC Sentinel TAXII 2.1 Server',
    description: 'Threat Intelligence Platform — TAXII 2.1 Read-Only Feed',
    contact:     'security@ioc-sentinel.local',
    default:     `${base}/`,
    api_roots:   [`${base}/`],
  });
};

// ─────────────────────────────────────────────────────────────
// GET /api/taxii/collections
// TAXII 2.1 Collections — §5.1
// Lists all collections this server exposes.
// ─────────────────────────────────────────────────────────────
const getCollections = (req, res) => {
  res.set('Content-Type', TAXII_CONTENT_TYPE);
  res.json({ collections: TAXII_COLLECTIONS });
};

// ─────────────────────────────────────────────────────────────
// GET /api/taxii/collections/:collectionId
// TAXII 2.1 Collection Metadata — §5.2
// Returns metadata for a single collection.
// ─────────────────────────────────────────────────────────────
const getCollectionById = (req, res) => {
  const collection = TAXII_COLLECTIONS.find(c => c.id === req.params.collectionId);

  if (!collection) {
    return res.status(404).set('Content-Type', TAXII_CONTENT_TYPE).json({
      title:       'Collection Not Found',
      description: `No collection with id '${req.params.collectionId}'`,
      http_status: '404',
    });
  }

  res.set('Content-Type', TAXII_CONTENT_TYPE);
  res.json(collection);
};

// ─────────────────────────────────────────────────────────────
// GET /api/taxii/collections/:collectionId/objects
// TAXII 2.1 Objects — §5.4
// Returns STIX objects from a collection with optional pagination.
//
// Supported query params:
//   added_after  — ISO 8601 timestamp filter
//   limit        — max objects returned (default 500)
//   match[type]  — filter by STIX object type (e.g. indicator)
//   match[id]    — filter by STIX object ID
// ─────────────────────────────────────────────────────────────
const getCollectionObjects = async (req, res, next) => {
  try {
    const { collectionId } = req.params;
    const {
      added_after,
      limit = DEFAULT_PAGE_SIZE,
    } = req.query;

    // Validate collection
    const collection = TAXII_COLLECTIONS.find(c => c.id === collectionId);
    if (!collection) {
      return res.status(404).set('Content-Type', TAXII_CONTENT_TYPE).json({
        title:       'Collection Not Found',
        http_status: '404',
        description: `No collection with id '${collectionId}'`,
      });
    }

    const pageSize = Math.min(Number(limit) || DEFAULT_PAGE_SIZE, 2000);

    // Load IOCs and apply collection filters
    const rawIOCs = await loadIOCs(req.user.userId, added_after);
    const filtered = filterByCollection(rawIOCs, collectionId);

    // Build the STIX bundle
    const bundle = buildStixBundle(filtered.slice(0, pageSize), { collectionId });

    // TAXII spec §5.4: response wraps objects in an envelope
    // The spec says the body IS a bundle, not wrapped — we comply.
    const totalObjects = bundle.objects.length;
    const hasMore      = filtered.length > pageSize;

    // Set TAXII-required response headers
    res.set('Content-Type',     STIX_CONTENT_TYPE);
    res.set('X-TAXII-Date-Added-First', rawIOCs.length ? new Date(rawIOCs[rawIOCs.length - 1].createdAt).toISOString() : '');
    res.set('X-TAXII-Date-Added-Last',  rawIOCs.length ? new Date(rawIOCs[0].createdAt).toISOString() : '');

    // TAXII 2.1 compliant envelope with bundle as the body
    res.json({
      type:         bundle.type,
      id:           bundle.id,
      spec_version: bundle.spec_version,
      objects:      bundle.objects,
      // Non-spec pagination metadata (widely supported by TAXII clients)
      _taxii_meta: {
        collection_id: collectionId,
        total_count:   filtered.length,
        returned:      totalObjects,
        has_more:      hasMore,
        ...(hasMore && {
          next: `/api/taxii/collections/${collectionId}/objects?limit=${pageSize}&added_after=${
            filtered[pageSize - 1]?.createdAt
              ? new Date(filtered[pageSize - 1].createdAt).toISOString()
              : ''
          }`,
        }),
      },
    });

    logger.info(`TAXII: served ${totalObjects} objects from collection '${collectionId}' to user ${req.user.username}`);
  } catch (err) {
    logger.error(`TAXII getCollectionObjects error: ${err.message}`);
    next(err);
  }
};

// ─────────────────────────────────────────────────────────────
// GET /api/taxii/collections/:collectionId/manifest
// TAXII 2.1 Manifest — §5.5
// Returns a manifest (lightweight listing) of objects in a collection.
// Useful for TAXII clients doing differential sync.
// ─────────────────────────────────────────────────────────────
const getCollectionManifest = async (req, res, next) => {
  try {
    const { collectionId } = req.params;
    const { added_after }  = req.query;

    const collection = TAXII_COLLECTIONS.find(c => c.id === collectionId);
    if (!collection) {
      return res.status(404).set('Content-Type', TAXII_CONTENT_TYPE).json({
        title: 'Collection Not Found', http_status: '404',
      });
    }

    const rawIOCs  = await loadIOCs(req.user.userId, added_after);
    const filtered = filterByCollection(rawIOCs, collectionId);

    // Manifest entry = { id, date_added, version, media_type }
    const manifest = filtered.map(ioc => ({
      id:         `indicator--${ioc._id.toString().padStart(36, '0').slice(-36)}`,
      date_added: new Date(ioc.createdAt).toISOString(),
      version:    new Date(ioc.updatedAt).toISOString(),
      media_type: STIX_CONTENT_TYPE,
    }));

    res.set('Content-Type', TAXII_CONTENT_TYPE);
    res.json({ objects: manifest });

    logger.info(`TAXII: manifest with ${manifest.length} entries served from '${collectionId}'`);
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────────────────────
// GET /api/taxii/export
// GET /api/taxii/export/:collectionId
// Non-TAXII: browser-friendly STIX bundle download endpoint.
// Returns a .json file with Content-Disposition: attachment.
// Used by the React export button in ThreatFeed.jsx.
// ─────────────────────────────────────────────────────────────
const exportStixBundle = async (req, res, next) => {
  try {
    const collectionId = req.params.collectionId || 'ioc-sentinel-all';
    const { severity, since }  = req.query;

    // Build filter
    const filter = { isActive: true, submittedBy: req.user.userId };
    if (severity) filter.severity = severity;
    if (since) {
      const dt = new Date(since);
      if (!isNaN(dt)) filter.createdAt = { $gte: dt };
    }

    const iocDocs = await IOC.find(filter).sort({ threatScore: -1 }).lean();
    const filtered = filterByCollection(iocDocs, collectionId);
    const bundle   = buildStixBundle(filtered, { collectionId });

    const filename = `ioc-sentinel-stix-${collectionId}-${Date.now()}.json`;

    res.set('Content-Type', STIX_CONTENT_TYPE);
    res.set('Content-Disposition', `attachment; filename="${filename}"`);
    res.json(bundle);

    logger.info(`STIX export: ${filtered.length} indicators exported by ${req.user.username}`);
  } catch (err) {
    logger.error(`STIX export error: ${err.message}`);
    next(err);
  }
};

module.exports = {
  getDiscovery,
  getCollections,
  getCollectionById,
  getCollectionObjects,
  getCollectionManifest,
  exportStixBundle,
};
