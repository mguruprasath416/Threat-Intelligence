// ============================================================
// controllers/authController.js — AUTHENTICATION LOGIC
// ============================================================
// Handles user registration, login, and token management.
//
// Authentication flow:
//   1. User POSTs credentials to /api/auth/login
//   2. Server verifies password against bcrypt hash in DB
//   3. Server generates a JWT (JSON Web Token)
//   4. Client stores JWT (usually in memory or httpOnly cookie)
//   5. Client sends JWT in Authorization header on every request
//   6. authMiddleware validates the JWT on protected routes
//
// JWT structure: header.payload.signature
//   payload contains: { userId, role, iat, exp }
//   exp = expiry timestamp (7 days by default)
//
// Why JWT over sessions?
//   - Stateless — no session storage needed on server
//   - Works across multiple server instances (horizontal scaling)
//   - Self-contained — role info is in the token
// ============================================================

const jwt  = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

// ── Helper: Generate JWT ───────────────────────────────────
const generateToken = (userId, role) => {
  return jwt.sign(
    { userId, role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE || '7d' }
  );
};

// ── Helper: Send Token Response ───────────────────────────
// Builds the standardized auth response
const sendTokenResponse = (user, statusCode, res) => {
  const token = generateToken(user._id, user.role);

  // Cookie config for added security (in addition to returning in body)
  const cookieOptions = {
    expires:  new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    httpOnly: true,   // Not accessible via JavaScript (XSS protection)
    secure:   process.env.NODE_ENV === 'production', // HTTPS only in prod
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

// ── POST /api/auth/register ───────────────────────────────
const register = async (req, res, next) => {
  try {
    const { username, email, password, firstName, lastName } = req.body;

    // Basic field validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'username, email and password are required',
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const field = existingUser.email === email ? 'Email' : 'Username';
      return res.status(409).json({ // 409 Conflict
        success: false,
        message: `${field} already in use`,
      });
    }

    // Create user — password hashing happens in the model's pre-save hook
    const user = await User.create({
      username,
      email,
      password,
      firstName,
      lastName,
      // First registered user gets admin role automatically
      role: (await User.countDocuments({})) === 0 ? 'admin' : 'analyst',
    });

    logger.info(`New user registered: ${username} (${user.role})`);
    
    res.status(201).json({
      success: true,
      message: 'Account created successfully. Please sign in to continue.',
      user: {
        id:       user._id,
        username: user.username,
        email:    user.email,
        role:     user.role,
      },
    });

  } catch (err) {
    // Mongoose duplicate key error
    if (err.code === 11000) {
      return res.status(409).json({
        success: false,
        message: 'Username or email already exists',
      });
    }
    logger.error(`register error: ${err.message}`);
    next(err);
  }
};

// ── POST /api/auth/login ──────────────────────────────────
const login = async (req, res, next) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username/Email and password are required',
      });
    }

    // Allow login with either email or username
    const user = await User.findOne({
      $or: [
        { email:    identifier.toLowerCase() },
        { username: identifier },
      ]
    }).select('+password');

    if (!user) {
      // Intentionally vague error — don't reveal if email exists
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Account is deactivated. Contact your administrator.',
      });
    }

    // Compare entered password with stored bcrypt hash
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Update lastLogin timestamp
    user.lastLogin = new Date();
    await user.save({ validateBeforeSave: false }); // Skip full validation for this update

    logger.info(`User logged in: ${user.username}`);
    sendTokenResponse(user, 200, res);

  } catch (err) {
    logger.error(`login error: ${err.message}`);
    next(err);
  }
};

// ── GET /api/auth/me ──────────────────────────────────────
// Returns the currently authenticated user's profile
// req.user is set by authMiddleware after JWT verification
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
// Clears the auth cookie (JWT itself can't be invalidated server-side
// without a token blacklist — clearing cookie handles it for web clients)
const logout = (req, res) => {
  res
    .cookie('token', 'none', {
      expires:  new Date(Date.now() + 5 * 1000), // Expires in 5 seconds
      httpOnly: true,
    })
    .status(200)
    .json({ success: true, message: 'Logged out successfully' });
};

// ── PUT /api/auth/password ────────────────────────────────
// Change password for logged-in user
const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'currentPassword and newPassword are required',
      });
    }

    const user = await User.findById(req.user.userId).select('+password');
    const isValid = await user.comparePassword(currentPassword);

    if (!isValid) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    user.password = newPassword; // Pre-save hook will hash it
    await user.save();

    logger.info(`Password changed for user: ${user.username}`);
    sendTokenResponse(user, 200, res); // Send new token

  } catch (err) {
    logger.error(`changePassword error: ${err.message}`);
    next(err);
  }
};

module.exports = { register, login, getMe, logout, changePassword };
