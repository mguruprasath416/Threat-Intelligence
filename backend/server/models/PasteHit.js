// ============================================================
// models/PasteHit.js — PASTE HIT MODEL
// ============================================================
// Stores detected matches from paste monitoring (Pastebin, etc.)
// Tracks IOC matches, credential dumps, and other sensitive patterns
// ============================================================

const mongoose = require('mongoose');

const pasteHitSchema = new mongoose.Schema({
  pasteKey: {
    type: String,
    required: true,
    index: true
  },
  pasteUrl: {
    type: String,
    required: true
  },
  pasteTitle: {
    type: String,
    default: 'Untitled'
  },
  matchType: {
    type: String,
    enum: ['ioc-match', 'credential', 'email-dump', 'crypto-wallet', 'cve-reference', 'keyword-match'],
    required: true,
    index: true
  },
  matchedValue: {
    type: String,
    required: true
  },
  rawSnippet: {
    type: String,
    default: ''
  },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low'],
    default: 'Medium',
    index: true
  },
  source: {
    type: String,
    default: 'pastebin',
    index: true
  },
  dateFound: {
    type: Date,
    default: Date.now,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  iocId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'IOC',
    index: true
  },
  tags: [{
    type: String
  }]
}, {
  timestamps: true
});

// Compound index for efficient queries
pasteHitSchema.index({ userId: 1, dateFound: -1 });
pasteHitSchema.index({ matchType: 1, dateFound: -1 });
pasteHitSchema.index({ severity: 1, dateFound: -1 });

module.exports = mongoose.model('PasteHit', pasteHitSchema);
