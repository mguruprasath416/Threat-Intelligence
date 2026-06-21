// ============================================================
// controllers/huntController.js — THREAT HUNTING CONTROLLER
// ============================================================
// Handles threat hunting rule generation requests
// ============================================================

const { generateHuntRule } = require('../services/huntService');
const logger = require('../utils/logger');

// ── POST /api/hunt/generate ─────────────────────────────────
// Generate hunting rules from selected IOCs
const generateRule = async (req, res, next) => {
  try {
    const { iocIds, format } = req.body;

    // Validate input
    if (!iocIds || !Array.isArray(iocIds) || iocIds.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'iocIds array is required and must not be empty'
      });
    }

    if (!format || !['yara', 'sigma', 'kql', 'spl'].includes(format.toLowerCase())) {
      return res.status(400).json({
        success: false,
        message: 'format is required and must be one of: yara, sigma, kql, spl'
      });
    }

    // Generate the rule
    const result = await generateHuntRule(iocIds, format);

    res.status(200).json({
      success: true,
      data: result
    });

  } catch (err) {
    logger.error(`generateRule error: ${err.message}`);
    res.status(500).json({
      success: false,
      message: err.message || 'Failed to generate hunting rule'
    });
  }
};

module.exports = {
  generateRule
};
