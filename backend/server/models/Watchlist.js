// ============================================================
// models/Watchlist.js — USER WATCHLIST SCHEMA
// ============================================================

const mongoose = require('mongoose');

const watchlistSchema = new mongoose.Schema({
  userId: {
    type:     mongoose.Schema.Types.ObjectId,
    ref:      'User',
    required: true,
    unique:   true, // One watchlist configuration per analyst
  },
  patterns: {
    type:     [String],
    default:  [], // e.g. ['evil.com', 'ransomware', '1.2.3.4']
  },
  createdAt: {
    type:     Date,
    default:  Date.now,
  },
  updatedAt: {
    type:     Date,
    default:  Date.now,
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Watchlist', watchlistSchema);
