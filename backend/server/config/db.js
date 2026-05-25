// ============================================================
// config/db.js — MONGODB CONNECTION
// ============================================================
// Handles connecting to MongoDB using Mongoose.
// Mongoose is an ODM (Object Document Mapper) — it lets us
// define schemas/models and interact with MongoDB using
// JavaScript objects instead of raw MongoDB queries.
//
// Why separate this from server.js?
//   - Can be reused in tests
//   - Centralizes DB config
//   - Easier to swap databases later
// ============================================================

const mongoose = require('mongoose');
const logger   = require('../utils/logger');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      // These options prevent deprecation warnings
      useNewUrlParser:    true,
      useUnifiedTopology: true,
    });

    logger.info(`✅ MongoDB Connected: ${conn.connection.host}`);

    // ── Mongoose Event Listeners ──────────────────────────────
    // These fire on connection issues AFTER initial connect
    mongoose.connection.on('error', (err) => {
      logger.error(`MongoDB connection error: ${err}`);
    });

    mongoose.connection.on('disconnected', () => {
      logger.warn('MongoDB disconnected. Attempting to reconnect...');
    });

    mongoose.connection.on('reconnected', () => {
      logger.info('MongoDB reconnected');
    });

  } catch (error) {
    logger.error(`MongoDB connection failed: ${error.message}`);
    throw error; // Bubble up so server.js can exit
  }
};

// Graceful shutdown — close DB when Node process is killed
// This ensures no data loss on CTRL+C or server restart
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  logger.info('MongoDB connection closed due to app termination');
  process.exit(0);
});

module.exports = { connectDB };
