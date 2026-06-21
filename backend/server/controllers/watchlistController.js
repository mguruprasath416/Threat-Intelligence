// ============================================================
// controllers/watchlistController.js — WATCHLIST CONTROLLER
// ============================================================

const Watchlist = require('../models/Watchlist');
const logger = require('../utils/logger');

// Get current user's watchlist
const getWatchlist = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    let watchlist = await Watchlist.findOne({ userId });

    if (!watchlist) {
      // Return empty format if it doesn't exist yet
      return res.status(200).json({
        success:  true,
        userId,
        patterns: []
      });
    }

    res.status(200).json({
      success:  true,
      userId:   watchlist.userId,
      patterns: watchlist.patterns
    });
  } catch (err) {
    logger.error(`Error in getWatchlist: ${err.message}`);
    next(err);
  }
};

// Update/Save user's watchlist patterns
const updateWatchlist = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const { patterns } = req.body;

    if (!Array.isArray(patterns)) {
      return res.status(400).json({
        success: false,
        message: 'patterns field must be an array of strings'
      });
    }

    // Clean and validate pattern values
    const cleanedPatterns = patterns
      .map(p => typeof p === 'string' ? p.trim() : '')
      .filter(p => p.length > 0);

    const watchlist = await Watchlist.findOneAndUpdate(
      { userId },
      {
        $set: {
          patterns: cleanedPatterns,
          updatedAt: new Date()
        }
      },
      { new: true, upsert: true } // Create if doesn't exist
    );

    res.status(200).json({
      success:  true,
      message:  'Watchlist updated successfully',
      patterns: watchlist.patterns
    });
  } catch (err) {
    logger.error(`Error in updateWatchlist: ${err.message}`);
    next(err);
  }
};

module.exports = {
  getWatchlist,
  updateWatchlist
};
