// ============================================================
// routes/graphRoutes.js — IOC RELATIONSHIP GRAPH ROUTES
// ============================================================

const express = require('express');
const router  = express.Router();
const { getGraphData } = require('../controllers/graphController');
const { protect } = require('../middleware/authMiddleware');

// Protect all routes in this file
router.use(protect);

// GET /api/graph/:iocId
router.get('/:iocId', getGraphData);

module.exports = router;
