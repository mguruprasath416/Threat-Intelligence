// ============================================================
// routes/watchlistRoutes.js — WATCHLIST CONFIG ROUTING
// ============================================================

const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const {
  getWatchlist,
  updateWatchlist
} = require('../controllers/watchlistController');

// All watchlist routes require auth
router.use(protect);

router.route('/')
  .get(getWatchlist)
  .post(updateWatchlist);

module.exports = router;
// ============================================================
