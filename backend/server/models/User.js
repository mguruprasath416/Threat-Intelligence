// ============================================================
// models/User.js — USER DATABASE SCHEMA
// ============================================================
// Defines the User document structure in MongoDB.
// Handles password hashing automatically using bcrypt.
//
// Security practices used:
//   - Passwords are hashed with bcrypt (never stored as plaintext)
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

  // NEVER store raw passwords — bcrypt hashes them
  // select: false means password is NOT returned in queries by default
  password: {
    type:     String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
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

// ── Pre-Save Hook: Hash Password ───────────────────────────
// This runs AUTOMATICALLY before every .save() call
// Only re-hashes if the password field was actually changed
// (prevents double-hashing on other field updates)
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  // saltRounds: 12 = good balance of security vs performance
  // Higher = slower hashing = harder to brute force
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// ── Instance Method: Compare Password ─────────────────────
// Used during login to check if entered password matches hash
// Returns true/false
UserSchema.methods.comparePassword = async function (enteredPassword) {
  return bcrypt.compare(enteredPassword, this.password);
};

// ── Virtual: Full Name ─────────────────────────────────────
UserSchema.virtual('fullName').get(function () {
  return `${this.firstName || ''} ${this.lastName || ''}`.trim();
});

module.exports = mongoose.model('User', UserSchema);
