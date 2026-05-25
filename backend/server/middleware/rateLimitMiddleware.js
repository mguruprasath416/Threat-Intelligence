// ============================================================
// middleware/rateLimitMiddleware.js — RATE LIMITING
// ============================================================
// Prevents API abuse by limiting how many requests a single
// IP address can make within a time window.
//
// Why rate limit?
//   - Protects against brute force attacks on /api/auth/login
//   - Prevents accidental/malicious flooding of external APIs
//     (VirusTotal has a 4 req/min limit — burning it = no enrichment)
//   - DDoS mitigation
//   - Fair usage enforcement
//
// We use express-rate-limit which uses in-memory storage by default.
// For production with multiple servers, swap to redis store:
//   npm install rate-limit-redis
// ============================================================

const rateLimit = require('express-rate-limit');
const logger    = require('../utils/logger');

// ── General API Rate Limiter ───────────────────────────────
// Applied to all /api/* routes
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max:      100,             // Max 100 requests per IP per window
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again in 15 minutes.',
  },
  standardHeaders: true,  // Return rate limit info in RateLimit-* headers
  legacyHeaders:   false,  // Disable X-RateLimit-* headers
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip} on ${req.path}`);
    res.status(429).json(options.message);
  },
});

// ── Strict Limiter for Auth Routes ────────────────────────
// Extra tight on login to prevent brute force password guessing
// 10 attempts per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      10,
  message: {
    success: false,
    message: 'Too many login attempts. Account temporarily locked for 15 minutes.',
  },
  skipSuccessfulRequests: true, // Don't count successful logins against the limit
  handler: (req, res, next, options) => {
    logger.warn(`Auth rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  },
});

// ── IOC Search Limiter ────────────────────────────────────
// Each IOC search triggers VirusTotal (4 req/min free tier)
// Limit to 30 IOC searches per 10 minutes to stay within VT quota
const iocSearchLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max:      30,
  message: {
    success: false,
    message: 'IOC search rate limit reached. Please wait before submitting more indicators.',
  },
  handler: (req, res, next, options) => {
    logger.warn(`IOC search rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json(options.message);
  },
});

module.exports = generalLimiter;
module.exports.authLimiter      = authLimiter;
module.exports.iocSearchLimiter = iocSearchLimiter;
