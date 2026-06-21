// ============================================================
// models/Alert.js — WATCHLIST MATCH ALERT RECORDS
// ============================================================

const mongoose = require('mongoose');

const alertSchema = new mongoose.Schema({
  userId: {
    type:     mongoose.Schema.Types.ObjectId,
    ref:      'User',
    required: true,
  },
  iocId: {
    type:     mongoose.Schema.Types.ObjectId,
    ref:      'IOC',
  },
  iocIndicator: {
    type:     String,
    required: true,
  },
  iocType: {
    type:     String,
    required: true,
  },
  severity: {
    type:     String,
    default:  'Medium',
  },
  matchedPattern: {
    type:     String,
    required: true,
  },
  read: {
    type:     Boolean,
    default:  false,
  },
  createdAt: {
    type:     Date,
    default:  Date.now,
  }
});

// Index for quick queries of unread alerts per user
alertSchema.index({ userId: 1, read: 1, createdAt: -1 });

module.exports = mongoose.model('Alert', alertSchema);
