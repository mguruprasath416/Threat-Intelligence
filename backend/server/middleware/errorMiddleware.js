// ============================================================
// middleware/errorMiddleware.js — GLOBAL ERROR HANDLER
// ============================================================
// This is the LAST middleware in app.js — it catches any error
// passed via next(err) from any controller or middleware above.
//
// Why centralize error handling?
//   - Consistent error response format across ALL endpoints
//   - No try/catch boilerplate in controllers (just next(err))
//   - One place to control what error info leaks to clients
//   - Logging in one place
//
// Error types handled:
//   - Mongoose CastError (invalid MongoDB ID format)
//   - Mongoose ValidationError (schema validation failed)
//   - Mongoose duplicate key (unique constraint violated)
//   - JWT errors (handled in authMiddleware but caught here too)
//   - Generic 500 errors
// ============================================================

const logger = require('../utils/logger');

const errorMiddleware = (err, req, res, next) => {
  // Clone the error so we can modify it without side effects
  let error = { ...err };
  error.message = err.message;

  // Log all errors (with stack in development)
  logger.error(
    process.env.NODE_ENV === 'development'
      ? `${err.message}\n${err.stack}`
      : err.message
  );

  // ── Mongoose: Invalid ObjectId ─────────────────────────
  // Happens when req.params.id is not a valid MongoDB ObjectId
  // e.g. GET /api/ioc/not-a-valid-id
  if (err.name === 'CastError') {
    error.statusCode = 400;
    error.message    = `Invalid ${err.path}: ${err.value}`;
  }

  // ── Mongoose: Validation Error ─────────────────────────
  // Happens when schema validators fail on create/update
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(e => e.message);
    error.statusCode = 400;
    error.message    = messages.join('. ');
  }

  // ── Mongoose: Duplicate Key ────────────────────────────
  // Happens when unique index constraint is violated
  // err.code 11000 = MongoDB duplicate key error code
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    error.statusCode = 409; // 409 Conflict
    error.message    = `${field} already exists`;
  }

  // ── JWT Errors ─────────────────────────────────────────
  if (err.name === 'JsonWebTokenError') {
    error.statusCode = 401;
    error.message    = 'Invalid token';
  }

  if (err.name === 'TokenExpiredError') {
    error.statusCode = 401;
    error.message    = 'Token expired';
  }

  // ── Send Response ──────────────────────────────────────
  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || 'Internal Server Error',
    // Only include stack trace in development (never expose internals in prod)
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
};

module.exports = errorMiddleware;
