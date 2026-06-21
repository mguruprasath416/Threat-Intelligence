// ============================================================
// routes/huntRoutes.js — THREAT HUNTING ROUTES
// ============================================================

const express = require('express');
const router  = express.Router();

const { generateRule } = require('../controllers/huntController');
const { protect } = require('../middleware/authMiddleware');

// All hunt routes require authentication
router.use(protect);

// ── Hunt Routes ─────────────────────────────────────────────
// POST /api/hunt/generate → Generate hunting rule from IOCs
router.post('/generate', generateRule);

module.exports = router;
