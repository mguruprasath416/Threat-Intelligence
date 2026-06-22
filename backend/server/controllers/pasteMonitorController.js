// ============================================================
// controllers/pasteMonitorController.js — PASTE MONITOR CONTROLLER
// ============================================================
// Handles API endpoints for paste monitoring features
// Recent hits, stats, and watchlist management
// ============================================================

const PasteHit = require('../models/PasteHit');
const WatchlistPattern = require('../models/WatchlistPattern');
const logger = require('../utils/logger');

// ── GET /api/paste/recent ─────────────────────────────────────
// Returns last 50 paste hits from DB, sorted by dateAdded desc
const getRecentPastes = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const limit = parseInt(req.query.limit) || 50;
    
    const pastes = await PasteHit.find({ userId })
      .sort({ dateFound: -1 })
      .limit(limit)
      .lean();
    
    res.status(200).json({
      success: true,
      data: pastes
    });
  } catch (err) {
    logger.error(`getRecentPastes error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/paste/stats ───────────────────────────────────────
// Returns counts grouped by matchType and severity for last 7 days
const getPasteStats = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    
    const stats = await PasteHit.aggregate([
      {
        $match: {
          userId: userId,
          dateFound: { $gte: sevenDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            matchType: '$matchType',
            severity: '$severity'
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);
    
    // Format results
    const formattedStats = stats.map(stat => ({
      matchType: stat._id.matchType,
      severity: stat._id.severity,
      count: stat.count
    }));
    
    // Get total count
    const totalCount = await PasteHit.countDocuments({
      userId: userId,
      dateFound: { $gte: sevenDaysAgo }
    });
    
    res.status(200).json({
      success: true,
      data: {
        stats: formattedStats,
        total: totalCount,
        period: '7 days'
      }
    });
  } catch (err) {
    logger.error(`getPasteStats error: ${err.message}`);
    next(err);
  }
};

// ── POST /api/paste/watchlist ───────────────────────────────────
// Add a keyword/regex pattern to watchlist
const addWatchlistPattern = async (req, res, next) => {
  try {
    const { pattern, patternType, description } = req.body;
    const userId = req.user.userId;
    
    if (!pattern) {
      return res.status(400).json({
        success: false,
        message: 'Pattern is required'
      });
    }
    
    if (patternType && !['keyword', 'regex'].includes(patternType)) {
      return res.status(400).json({
        success: false,
        message: 'Pattern type must be either "keyword" or "regex"'
      });
    }
    
    // Validate regex if patternType is regex
    if (patternType === 'regex') {
      try {
        new RegExp(pattern);
      } catch (err) {
        return res.status(400).json({
          success: false,
          message: 'Invalid regex pattern'
        });
      }
    }
    
    const watchlistPattern = new WatchlistPattern({
      pattern,
      patternType: patternType || 'keyword',
      userId,
      description: description || ''
    });
    
    await watchlistPattern.save();
    
    logger.info(`Watchlist pattern added by user ${userId}: ${pattern}`);
    
    res.status(201).json({
      success: true,
      data: watchlistPattern
    });
  } catch (err) {
    logger.error(`addWatchlistPattern error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/paste/watchlist ────────────────────────────────────
// Return current user's watchlist patterns
const getWatchlistPatterns = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    
    const patterns = await WatchlistPattern.find({ userId })
      .sort({ createdAt: -1 })
      .lean();
    
    res.status(200).json({
      success: true,
      data: patterns
    });
  } catch (err) {
    logger.error(`getWatchlistPatterns error: ${err.message}`);
    next(err);
  }
};

// ── DELETE /api/paste/watchlist/:id ──────────────────────────────
// Remove a pattern from watchlist
const deleteWatchlistPattern = async (req, res, next) => {
  try {
    const { id } = req.params;
    const userId = req.user.userId;
    
    const pattern = await WatchlistPattern.findOneAndDelete({
      _id: id,
      userId
    });
    
    if (!pattern) {
      return res.status(404).json({
        success: false,
        message: 'Pattern not found or does not belong to user'
      });
    }
    
    logger.info(`Watchlist pattern deleted by user ${userId}: ${pattern.pattern}`);
    
    res.status(200).json({
      success: true,
      message: 'Pattern deleted successfully'
    });
  } catch (err) {
    logger.error(`deleteWatchlistPattern error: ${err.message}`);
    next(err);
  }
};

module.exports = {
  getRecentPastes,
  getPasteStats,
  addWatchlistPattern,
  getWatchlistPatterns,
  deleteWatchlistPattern
};
