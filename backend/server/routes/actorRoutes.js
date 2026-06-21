// ============================================================
// routes/actorRoutes.js — THREAT ACTOR API ROUTES
// ============================================================
// All routes are protected — require valid JWT.
// DELETE is admin-only.
//
// Route map:
//   GET    /api/actors/stats        → aggregated stats (before /:id)
//   GET    /api/actors              → list actors
//   POST   /api/actors              → create actor
//   GET    /api/actors/:id          → get actor detail
//   PUT    /api/actors/:id          → update actor
//   DELETE /api/actors/:id          → delete actor (admin)
//   POST   /api/actors/:id/iocs     → link IOCs
//   DELETE /api/actors/:id/iocs/:iocId → unlink IOC
// ============================================================

const express = require('express');
const router  = express.Router();

const { protect, authorize } = require('../middleware/authMiddleware');
const {
  getActors,
  createActor,
  getActorById,
  updateActor,
  deleteActor,
  linkIOCs,
  unlinkIOC,
  getActorStats,
} = require('../controllers/actorController');

// ── Auth guard on all routes ───────────────────────────────
router.use(protect);

// ── Stats (must come BEFORE /:id to avoid route collision) ─
router.get('/stats', getActorStats);

// ── CRUD ──────────────────────────────────────────────────
router.route('/')
  .get(getActors)
  .post(createActor);

router.route('/:id')
  .get(getActorById)
  .put(updateActor)
  .delete(authorize('admin'), deleteActor);

// ── IOC Linking ───────────────────────────────────────────
router.post('/:id/iocs', linkIOCs);
router.delete('/:id/iocs/:iocId', unlinkIOC);

module.exports = router;
