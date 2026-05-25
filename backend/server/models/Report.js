// ============================================================
// models/Report.js — REPORT DATABASE SCHEMA
// ============================================================
// A Report is a saved snapshot of an analyst's investigation.
// It bundles together a set of IOCs with findings and metadata.
//
// Use cases:
//   - Export findings to share with team
//   - Document incident response actions
//   - Track repeated threat campaigns
// ============================================================

const mongoose = require('mongoose');

const ReportSchema = new mongoose.Schema({

  title: {
    type:     String,
    required: [true, 'Report title is required'],
    trim:     true,
    maxlength: [200, 'Title too long'],
  },

  description: {
    type: String,
    trim: true,
  },

  // Type of report being generated
  reportType: {
    type:    String,
    enum:    ['incident', 'campaign', 'threat_actor', 'daily_summary', 'custom'],
    default: 'custom',
  },

  // ── IOCs Included in this Report ────────────────────────
  // Array of references to IOC documents
  iocs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref:  'IOC',
  }],

  // Summary statistics captured at report creation time
  // (snapshots so report stays accurate even if IOCs change)
  summary: {
    totalIOCs:      { type: Number, default: 0 },
    criticalCount:  { type: Number, default: 0 },
    highCount:      { type: Number, default: 0 },
    mediumCount:    { type: Number, default: 0 },
    lowCount:       { type: Number, default: 0 },
    topThreatTypes: [String], // e.g. ['phishing', 'malware', 'c2']
  },

  // ── Analyst Notes ────────────────────────────────────────
  findings: {
    type: String, // Free-form markdown text
    trim: true,
  },

  recommendations: {
    type: String,
    trim: true,
  },

  // Who created the report
  createdBy: {
    type:     mongoose.Schema.Types.ObjectId,
    ref:      'User',
    required: true,
  },

  // Status lifecycle: draft → published → archived
  status: {
    type:    String,
    enum:    ['draft', 'published', 'archived'],
    default: 'draft',
  },

  // Tags for searching reports later
  tags: [String],

}, {
  timestamps: true,
  toJSON: { virtuals: true },
});

module.exports = mongoose.model('Report', ReportSchema);
