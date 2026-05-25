// ============================================================
// middleware/authMiddleware.js — JWT AUTHENTICATION GUARD
// ============================================================
// This middleware runs BEFORE controller functions on protected routes.
// It verifies the JWT token and attaches user info to req.user.
//
// How it works:
//   1. Reads token from Authorization header: "Bearer <token>"
//      OR from the httpOnly cookie
//   2. Verifies token signature using JWT_SECRET
//   3. Checks token hasn't expired
//   4. Attaches decoded payload to req.user
//   5. Calls next() to proceed to the controller
//
// Two exported functions:
//   protect      → just checks "are you logged in?"
//   authorize()  → checks "do you have the right role?"
// ============================================================

const jwt    = require('jsonwebtoken');
const User   = require('../models/User');
const logger = require('../utils/logger');

// ── protect: Verify JWT ────────────────────────────────────
// Use this on any route that requires authentication
const protect = async (req, res, next) => {
  let token;

  // Extract token from Authorization header (preferred for APIs)
  if (req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1]; // "Bearer abc123" → "abc123"
  }
  // Fallback to cookie (for browser-based sessions)
  else if (req.cookies?.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'No authentication token provided. Please log in.',
    });
  }

  try {
    // Verify signature + expiry in one step
    // Throws JsonWebTokenError if invalid, TokenExpiredError if expired
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Attach decoded payload to request
    // decoded = { userId, role, iat (issued at), exp (expiry) }
    req.user = decoded;

    // Optional: verify user still exists in DB
    // (catches case where account was deleted after token was issued)
    const user = await User.findById(decoded.userId).select('isActive role username');
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'User account not found or deactivated',
      });
    }

    // Refresh req.user with latest role (in case it was changed)
    req.user.role     = user.role;
    req.user.username = user.username;

    next(); // Token is valid — proceed to controller

  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Session expired. Please log in again.',
      });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token. Please log in again.',
      });
    }

    logger.error(`authMiddleware error: ${err.message}`);
    next(err);
  }
};

// ── authorize: Role-Based Access Control ──────────────────
// Use after protect — checks if user has required role(s)
// Usage: router.delete('/ioc/:id', protect, authorize('admin'), deleteIOC)
//
// authorize takes rest params so you can pass multiple allowed roles:
//   authorize('admin', 'analyst')
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      logger.warn(`Unauthorized access attempt by ${req.user.username} (role: ${req.user.role}) — required: ${roles.join('|')}`);
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role: ${roles.join(' or ')}`,
      });
    }
    next();
  };
};

module.exports = { protect, authorize };
