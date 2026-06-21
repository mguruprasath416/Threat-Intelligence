// ============================================================
// routes/taxiiRoutes.js — TAXII 2.1 + STIX EXPORT ROUTES
// ============================================================
// All routes require a valid JWT (Bearer token).
// TAXII 2.1 spec-compliant paths are grouped under /api/taxii.
//
// Route table:
//   GET /api/taxii/                                → Server Discovery
//   GET /api/taxii/collections                     → List collections
//   GET /api/taxii/collections/:id                 → Collection metadata
//   GET /api/taxii/collections/:id/objects         → STIX objects
//   GET /api/taxii/collections/:id/manifest        → Object manifest
//   GET /api/taxii/export                          → Download full bundle
//   GET /api/taxii/export/:collectionId            → Download filtered bundle
//
// TAXII 2.1 content negotiation note:
//   Responses use Content-Type: application/taxii+json;version=2.1 or
//   application/stix+json;version=2.1 depending on the endpoint.
//   See RFC 9110 §8.3 for Accept header handling.
// ============================================================

const express = require('express');
const router  = express.Router();

const { protect }              = require('../middleware/authMiddleware');
const {
  getDiscovery,
  getCollections,
  getCollectionById,
  getCollectionObjects,
  getCollectionManifest,
  exportStixBundle,
} = require('../controllers/taxiiController');

// All TAXII routes are protected
router.use(protect);

// ── Server Discovery ──────────────────────────────────────────
// Must respond to root path per TAXII spec §4.1
router.get('/', getDiscovery);

// ── Collections ───────────────────────────────────────────────
router.get('/collections',     getCollections);
router.get('/collections/:collectionId', getCollectionById);

// ── Collection Objects (main data endpoint) ───────────────────
// Placed before manifest to avoid param collision
router.get('/collections/:collectionId/objects',  getCollectionObjects);
router.get('/collections/:collectionId/manifest', getCollectionManifest);

// ── STIX Bundle Export (browser download) ────────────────────
// Not in TAXII spec — convenience endpoint for React UI
router.get('/export',                  exportStixBundle);
router.get('/export/:collectionId',    exportStixBundle);

module.exports = router;
