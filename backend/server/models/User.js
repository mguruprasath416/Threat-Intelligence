// ============================================================
// models/User.js — USER DATABASE SCHEMA
// ============================================================
// Defines the User document structure in MongoDB.
// Passwordless authentication via email OTP.
//
// Security practices used:
//   - No password stored — users authenticate via email OTP
//   - JWT tokens are used for session-less authentication
//   - Role-based access: 'analyst' vs 'admin'
// ============================================================

const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');

const UserSchema = new mongoose.Schema({

  username: {
    type:      String,
    required:  [true, 'Username is required'],
    unique:    true,
    trim:      true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [30, 'Username cannot exceed 30 characters'],
  },

  email: {
    type:     String,
    required: [true, 'Email is required'],
    unique:   true,
    trim:     true,
    lowercase: true,
    match:    [/^\S+@\S+\.\S+$/, 'Please enter a valid email'],
  },

  // Password field kept for backward compatibility but NOT required
  // (passwordless OTP flow is the primary auth method)
  password: {
    type:     String,
    required: false,
    select:   false,
  },

  // Role controls what API endpoints the user can access
  // analyst: read + search IOCs
  // admin:   full access including delete and user management
  role: {
    type:    String,
    enum:    ['analyst', 'admin'],
    default: 'analyst',
  },

  // Track when user last authenticated
  lastLogin: { type: Date, default: null },

  isActive: { type: Boolean, default: true },

  // Profile info
  firstName: { type: String, trim: true },
  lastName:  { type: String, trim: true },
  avatar:    { type: String, default: null }, // URL to avatar image

}, {
  timestamps: true,
  toJSON: { virtuals: true },
});

// ── Pre-Save Hook: Hash Password (kept for compat) ────────
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password') || !this.password) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// ── Virtual: Full Name ─────────────────────────────────────
UserSchema.virtual('fullName').get(function () {
  return `${this.firstName || ''} ${this.lastName || ''}`.trim();
});

module.exports = mongoose.model('User', UserSchema);
