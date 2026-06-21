// ============================================================
// models/IOC.js — IOC DATABASE SCHEMA
// ============================================================
// Defines the shape of an IOC (Indicator of Compromise) document
// in MongoDB. Every IOC stored in the DB follows this structure.
//
// What is an IOC?
//   Any piece of data that indicates a system may have been
//   compromised: a malicious IP, a phishing domain, a malware
//   hash, a suspicious URL.
//
// Mongoose Schema = blueprint for a MongoDB document.
// Mongoose Model  = the class used to read/write those documents.
// ============================================================

const mongoose = require('mongoose');

const IOCSchema = new mongoose.Schema({

  // ── Core Indicator ────────────────────────────────────────
  indicator: {
    type:     String,
    required: [true, 'IOC indicator value is required'],
    trim:     true,
    // index for fast lookups — we search by indicator constantly
    index:    true,
  },

  // Type of indicator — drives which enrichment APIs are called
  // ip → AbuseIPDB + VirusTotal
  // domain → VirusTotal + OTX
  // url → VirusTotal + OpenPhish
  // hash → VirusTotal (file reputation)
  iocType: {
    type:     String,
    enum:     ['ip', 'domain', 'url', 'hash', 'email'],
    required: true,
    index:    true,
  },

  // ── Severity Classification ───────────────────────────────
  // Calculated by threatScore.js based on reputation scores
  // Low: score 0-25 | Medium: 26-50 | High: 51-75 | Critical: 76-100
  severity: {
    type:    String,
    enum:    ['Low', 'Medium', 'High', 'Critical'],
    default: 'Low',
    index:   true,
  },

  // Numeric score 0-100, used for sorting and filtering
  threatScore: {
    type:    Number,
    min:     0,
    max:     100,
    default: 0,
  },

  // ── Source Information ─────────────────────────────────────
  // Which feed or user submitted this IOC
  source: {
    type:    String,
    default: 'manual', // 'manual' | 'virustotal' | 'otx' | 'openphish' | 'abuseipdb'
  },

  // ── Enrichment Data ───────────────────────────────────────
  // Raw data returned from threat intelligence APIs
  // Using Mixed type because structure varies per API
  enrichment: {
    virustotal: { type: mongoose.Schema.Types.Mixed, default: null },
    abuseipdb:  { type: mongoose.Schema.Types.Mixed, default: null },
    otx:        { type: mongoose.Schema.Types.Mixed, default: null },
  },

  // ── MITRE ATT&CK Mapping ──────────────────────────────────
  // Array of technique IDs this IOC maps to
  // e.g. ['T1566', 'T1071'] = Phishing + Application Layer Protocol
  mitreTechniques: [{
    techniqueId:   String, // e.g. 'T1566.001'
    techniqueName: String, // e.g. 'Spearphishing Attachment'
    tactic:        String, // e.g. 'Initial Access'
    killChainStage:String, // e.g. 'Delivery'
  }],

  // ── Geolocation (for IPs) ─────────────────────────────────
  geoLocation: {
    country:     { type: String, default: null },
    countryCode: { type: String, default: null },
    city:        { type: String, default: null },
    latitude:    { type: Number, default: null },
    longitude:   { type: Number, default: null },
    isp:         { type: String, default: null },
    asn:         { type: String, default: null },
  },

  // ── Tags ──────────────────────────────────────────────────
  // Free-form labels for filtering: 'malware', 'phishing', 'botnet'
  tags: [{ type: String, trim: true }],

  // ── Status ────────────────────────────────────────────────
  isActive:   { type: Boolean, default: true },  // false = archived/false positive
  isFP:       { type: Boolean, default: false }, // FP = False Positive flag

  // Last time enrichment data was refreshed from APIs
  lastEnriched: { type: Date, default: null },

  // Who submitted this IOC (references User model)
  submittedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref:  'User',
    default: null,
  },

}, {
  // Automatically adds createdAt and updatedAt fields
  timestamps: true,

  // Adds a virtual 'id' field (string version of _id)
  toJSON: { virtuals: true },
});

// Makes searching "indicator + type + user" combination very fast and unique per user
IOCSchema.index({ indicator: 1, iocType: 1, submittedBy: 1 }, { unique: true });

// ── Text Index ─────────────────────────────────────────────
// Enables full-text search across indicator and tags
IOCSchema.index({ indicator: 'text', tags: 'text' });

// ── Virtual: Age ───────────────────────────────────────────
// Not stored in DB — calculated on-the-fly when accessed
IOCSchema.virtual('ageInDays').get(function () {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

module.exports = mongoose.model('IOC', IOCSchema);
