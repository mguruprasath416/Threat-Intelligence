// ============================================================
// routes/pasteMonitorRoutes.js — PASTE MONITOR ROUTES
// ============================================================

const express = require('express');
const router = express.Router();

const {
  getRecentPastes,
  getPasteStats,
  addWatchlistPattern,
  getWatchlistPatterns,
  deleteWatchlistPattern
} = require('../controllers/pasteMonitorController');

const { protect } = require('../middleware/authMiddleware');

// All paste monitor routes require authentication
router.use(protect);

// ── Paste Hit Routes ───────────────────────────────────────────
router.get('/recent', getRecentPastes);
router.get('/stats', getPasteStats);

// ── Watchlist Pattern Routes ───────────────────────────────────
router.post('/watchlist', addWatchlistPattern);
router.get('/watchlist', getWatchlistPatterns);
router.delete('/watchlist/:id', deleteWatchlistPattern);

module.exports = router;
