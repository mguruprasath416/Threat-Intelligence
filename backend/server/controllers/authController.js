// ============================================================
// controllers/authController.js — AUTHENTICATION LOGIC (OTP)
// ============================================================
// Passwordless email OTP authentication flow:
//
//   STEP 1 — POST /api/auth/send-otp
//     → User provides their email
//     → Server generates a 6-digit OTP, saves it to OtpToken collection
//     → Sends OTP to user's email
//     → If email not registered → auto-creates user account (first-time users)
//
//   STEP 2 — POST /api/auth/verify-otp
//     → User provides email + OTP code
//     → Server validates OTP (correct code, not expired, attempts ≤ 5)
//     → Deletes used OTP, issues JWT
//     → Client stores JWT for subsequent requests
//
// Other routes:
//   GET  /api/auth/me       → Return current user profile
//   POST /api/auth/logout   → Clear auth cookie
// ============================================================

const crypto = require('crypto');
const jwt      = require('jsonwebtoken');
const User     = require('../models/User');
const OtpToken = require('../models/OtpToken');
const logger   = require('../utils/logger');
const { sendOtpEmail } = require('../services/emailService');

// ── Helper: Generate JWT ───────────────────────────────────
const generateToken = (userId, role) =>
  jwt.sign(
    { userId, role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );

// ── Helper: Send Token Response ───────────────────────────
const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user._id, user.role);

  const cookieOptions = {
    expires:  new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
  };

  res
    .status(statusCode)
    .cookie('token', token, cookieOptions)
    .json({
      success: true,
      token,
      user: {
        id:       user._id,
        username: user.username,
        email:    user.email,
        role:     user.role,
        fullName: user.fullName,
      },
    });
};

// ── Helper: Generate 6-digit OTP ──────────────────────────
const generateOtp = () =>
  String(crypto.randomInt(100000, 999999));

// ── POST /api/auth/send-otp ───────────────────────────────
// Step 1: Accept email, send OTP
const sendOtp = async (req, res, next) => {
  try {
    const { email } = req.body;

    if (!email || !email.trim()) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Basic email format check
    if (!/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // Find or create user (auto-register on first login)
    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      // Auto-create account — generate a username from the email prefix
      const emailPrefix = normalizedEmail.split('@')[0].replace(/[^a-z0-9_]/gi, '_');
      const userCount   = await User.countDocuments({});

      // Ensure username uniqueness by appending a short random suffix if needed
      let username = emailPrefix;
      const existing = await User.findOne({ username });
      if (existing) username = `${emailPrefix}_${crypto.randomInt(100, 999)}`;

      user = await User.create({
        username,
        email:    normalizedEmail,
        role:     userCount === 0 ? 'admin' : 'analyst', // First user = admin
        isActive: true,
      });

      logger.info(`Auto-registered new user: ${username} (${user.role})`);
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Account is deactivated. Contact your administrator.',
      });
    }

    // Delete any existing OTP for this email (only one active at a time)
    await OtpToken.deleteMany({ email: normalizedEmail });

    // Generate + store new OTP
    const otp = generateOtp();
    await OtpToken.create({ email: normalizedEmail, code: otp });

    // Send email
    await sendOtpEmail(normalizedEmail, otp);

    logger.info(`OTP sent to: ${normalizedEmail}`);

    res.status(200).json({
      success: true,
      message: 'Access code sent to your email. It expires in 10 minutes.',
      // In dev mode only — return OTP in response for easy testing
      ...(process.env.NODE_ENV === 'development' && { devOtp: otp }),
    });

  } catch (err) {
    logger.error(`sendOtp error: ${err.message}`);
    next(err);
  }
};

// ── POST /api/auth/verify-otp ─────────────────────────────
// Step 2: Verify OTP, issue JWT
const verifyOtp = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find OTP record
    const otpRecord = await OtpToken.findOne({ email: normalizedEmail });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: 'No active code found. Please request a new one.',
      });
    }

    // Check attempt limit (max 5)
    if (otpRecord.attempts >= 5) {
      await OtpToken.deleteOne({ _id: otpRecord._id });
      return res.status(429).json({
        success: false,
        message: 'Too many failed attempts. Please request a new code.',
      });
    }

    // Check if OTP matches
    if (otpRecord.code !== String(otp).trim()) {
      // Increment attempt counter
      otpRecord.attempts += 1;
      await otpRecord.save();

      const remaining = 5 - otpRecord.attempts;
      return res.status(401).json({
        success:   false,
        message:   `Incorrect code. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`,
        remaining,
      });
    }

    // OTP is valid — delete it (single-use)
    await OtpToken.deleteOne({ _id: otpRecord._id });

    // Load user
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Update lastLogin
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false });

    logger.info(`OTP verified — user logged in: ${user.username}`);
    sendTokenResponse(user, 200, res);

  } catch (err) {
    logger.error(`verifyOtp error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/auth/me ──────────────────────────────────────
const getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
};

// ── POST /api/auth/logout ─────────────────────────────────
const logout = (req, res) => {
  res
    .cookie('token', 'none', {
      expires:  new Date(Date.now() + 5 * 1000),
      httpOnly: true,
    })
    .status(200)
    .json({ success: true, message: 'Logged out successfully' });
};

module.exports = { sendOtp, verifyOtp, getMe, logout };
