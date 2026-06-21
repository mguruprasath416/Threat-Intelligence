// ============================================================
// models/ThreatActor.js — THREAT ACTOR / CAMPAIGN SCHEMA
// ============================================================
// Tracks APT groups, cybercriminal organizations, and campaigns.
// Links to IOC indicators to show operational footprint.
//
// Fields:
//   name         — official/primary name (e.g. "APT29", "Lazarus Group")
//   aliases      — alternative names / handles
//   country      — attributed nation-state (e.g. "Russia", "North Korea")
//   motivation   — primary motivation driving activity
//   ttps         — MITRE ATT&CK technique IDs used by this actor
//   linkedIOCs   — ObjectId references to IOC documents
//   campaigns    — named operations attributed to this actor
//   confidence   — analyst confidence in attribution (0-100)
//   isActive     — whether the actor is currently active/monitored
// ============================================================

const mongoose = require('mongoose');

const CampaignSchema = new mongoose.Schema({
  name:        { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  startDate:   { type: Date, default: null },
  endDate:     { type: Date, default: null },
  targets:     [{ type: String, trim: true }], // targeted sectors/orgs
  status:      {
    type:    String,
    enum:    ['active', 'historical', 'suspected'],
    default: 'historical',
  },
}, { _id: true });

const ThreatActorSchema = new mongoose.Schema({

  // ── Identity ───────────────────────────────────────────────
  name: {
    type:     String,
    required: [true, 'Actor name is required'],
    trim:     true,
    unique:   true,
    index:    true,
  },

  aliases: [{ type: String, trim: true }],

  // ── Attribution ────────────────────────────────────────────
  country: {
    type:    String,
    default: 'Unknown',
    trim:    true,
  },

  countryCode: {
    type:    String,
    default: null,
    trim:    true,
  },

  // Motivation: financial, espionage, hacktivism, sabotage, unknown
  motivation: {
    type:    String,
    enum:    ['financial', 'espionage', 'hacktivism', 'sabotage', 'disruption', 'unknown'],
    default: 'unknown',
  },

  // Threat actor category
  actorType: {
    type:    String,
    enum:    ['apt', 'criminal', 'hacktivist', 'insider', 'unknown'],
    default: 'unknown',
  },

  // Analyst confidence in attribution 0–100
  confidence: {
    type:    Number,
    min:     0,
    max:     100,
    default: 50,
  },

  // ── MITRE ATT&CK TTPs ─────────────────────────────────────
  // Techniques, Tactics, and Procedures used by this actor
  ttps: [{
    techniqueId:   { type: String, trim: true },  // e.g. 'T1566'
    techniqueName: { type: String, trim: true },  // e.g. 'Phishing'
    tactic:        { type: String, trim: true },  // e.g. 'Initial Access'
  }],

  // ── Linked IOCs ────────────────────────────────────────────
  // IOCs attributed to this actor's operations
  linkedIOCs: [{
    type: mongoose.Schema.Types.ObjectId,
    ref:  'IOC',
  }],

  // ── Campaigns ─────────────────────────────────────────────
  campaigns: [CampaignSchema],

  // ── Metadata ──────────────────────────────────────────────
  description: {
    type:    String,
    default: '',
    trim:    true,
  },

  targetSectors: [{ type: String, trim: true }],  // e.g. ['Finance', 'Healthcare']

  isActive: { type: Boolean, default: true },

  // Who created this actor profile
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref:  'User',
    default: null,
  },

}, {
  timestamps: true,
  toJSON: { virtuals: true },
});

// ── Text Index ─────────────────────────────────────────────
ThreatActorSchema.index({ name: 'text', aliases: 'text', description: 'text' });

// ── Virtual: IOC count ─────────────────────────────────────
ThreatActorSchema.virtual('iocCount').get(function () {
  return this.linkedIOCs?.length || 0;
});

module.exports = mongoose.model('ThreatActor', ThreatActorSchema);
