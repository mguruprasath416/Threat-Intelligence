// ============================================================
// routes/iocRoutes.js — UPDATED WITH POWER BI EXPORT
// ============================================================

const express = require('express');
const router  = express.Router();

const {
  searchIOC,
  getAllIOCs,
  getIOCStats,
  getIOCById,
  deleteIOC,
  flagFalsePositive,
} = require('../controllers/iocController');

const {
  exportForPowerBI,
  exportStatsForPowerBI,
} = require('../controllers/powerbiController');

const { protect, authorize }    = require('../middleware/authMiddleware');
const { iocSearchLimiter }      = require('../middleware/rateLimitMiddleware');

// All IOC routes require authentication
router.use(protect);

// ── Existing routes ────────────────────────────────────────
router.post('/search',    iocSearchLimiter, searchIOC);
router.get('/stats',      getIOCStats);
router.get('/',           getAllIOCs);
router.get('/:id',        getIOCById);
router.delete('/:id',     authorize('admin'), deleteIOC);
router.patch('/:id/flag', flagFalsePositive);

// ── Power BI Export Routes (NEW) ───────────────────────────
// GET /api/ioc/export/powerbi       → all IOCs flat JSON
// GET /api/ioc/export/powerbi-stats → KPI stats for cards
router.get('/export/powerbi',       exportForPowerBI);
router.get('/export/powerbi-stats', exportStatsForPowerBI);

module.exports = router;