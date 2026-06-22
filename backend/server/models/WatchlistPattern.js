// ============================================================
// models/WatchlistPattern.js — WATCHLIST PATTERN MODEL
// ============================================================
// Stores user-defined keyword/regex patterns for paste monitoring
// Users can add patterns to watch for in future paste scans
// ============================================================

const mongoose = require('mongoose');

const watchlistPatternSchema = new mongoose.Schema({
  pattern: {
    type: String,
    required: true,
    trim: true
  },
  patternType: {
    type: String,
    enum: ['keyword', 'regex'],
    required: true,
    default: 'keyword'
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  active: {
    type: Boolean,
    default: true,
    index: true
  },
  hitCount: {
    type: Number,
    default: 0
  },
  lastHit: {
    type: Date
  },
  description: {
    type: String,
    default: ''
  }
}, {
  timestamps: true
});

// Compound index for efficient queries
watchlistPatternSchema.index({ userId: 1, active: 1 });
watchlistPatternSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('WatchlistPattern', watchlistPatternSchema);
