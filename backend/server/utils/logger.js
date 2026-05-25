// ============================================================
// utils/logger.js — WINSTON LOGGER
// ============================================================
// Centralized logging using Winston.
// Why not just console.log?
//   - Log levels (info, warn, error, debug) for filtering
//   - Timestamps on every message
//   - Writes to files AND console simultaneously
//   - Log rotation (prevents log files growing forever)
//   - Structured JSON format for log aggregation tools (ELK, etc.)
//
// Log files:
//   logs/combined.log  → ALL logs (info + warn + error)
//   logs/error.log     → ERROR level only (for alerting)
// ============================================================

const winston = require('winston');
const path    = require('path');

const { combine, timestamp, printf, colorize, errors } = winston.format;

// ── Custom Log Format ──────────────────────────────────────
// Output: [2024-01-15 14:23:45] INFO: MongoDB Connected
const logFormat = printf(({ level, message, timestamp, stack }) => {
  // If this is an Error object, include the stack trace
  return `[${timestamp}] ${level.toUpperCase()}: ${stack || message}`;
});

const logger = winston.createLogger({
  // Default level — only log this level and above
  // Levels: error(0) > warn(1) > info(2) > debug(4)
  level: process.env.LOG_LEVEL || 'info',

  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }), // Capture stack traces from Error objects
    logFormat,
  ),

  transports: [
    // ── Console Transport ──────────────────────────────────
    // Colorized output for development readability
    new winston.transports.Console({
      format: combine(
        colorize({ all: true }), // Color-code by log level
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        logFormat,
      ),
      // Silence console logs during testing
      silent: process.env.NODE_ENV === 'test',
    }),

    // ── File Transport: All Logs ───────────────────────────
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/combined.log'),
      maxsize:  10 * 1024 * 1024, // 10MB max per file
      maxFiles: 5,                 // Keep last 5 rotated files
      tailable: true,
    }),

    // ── File Transport: Errors Only ────────────────────────
    // Separate file makes it easy to alert on errors
    new winston.transports.File({
      filename: path.join(__dirname, '../logs/error.log'),
      level:    'error',           // Only error-level logs
      maxsize:  5 * 1024 * 1024,  // 5MB max
      maxFiles: 3,
    }),
  ],

  // Don't crash on unhandled promise rejections in logger itself
  exitOnError: false,
});

module.exports = logger;
