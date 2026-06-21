// ============================================================
// models/OtpToken.js — OTP TOKEN SCHEMA
// ============================================================
// Stores short-lived OTP codes for email-based passwordless login.
// TTL index auto-deletes documents after `expiresAt`.
// ============================================================

const mongoose = require('mongoose');

const OtpTokenSchema = new mongoose.Schema({
  email: {
    type:     String,
    required: true,
    lowercase: true,
    trim:     true,
    index:    true,
  },

  // 6-digit OTP code (stored as plain text — it's short-lived & single-use)
  code: {
    type:     String,
    required: true,
  },

  // How many times the user tried to verify this OTP (max 5 attempts)
  attempts: {
    type:    Number,
    default: 0,
  },

  // TTL: MongoDB auto-removes this doc once expiresAt is reached
  expiresAt: {
    type:    Date,
    default: () => new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    index:   { expires: 0 }, // 0 = expire exactly at the field value
  },
});

module.exports = mongoose.model('OtpToken', OtpTokenSchema);
