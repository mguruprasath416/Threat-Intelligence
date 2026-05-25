// ============================================================
// routes/iocRoutes.js — IOC API ROUTES
// ============================================================
// Maps HTTP methods + paths to controller functions.
// Also applies middleware (auth, rate limiting) per route.
//
// Route summary:
//   POST   /api/ioc/search     → Search & enrich an IOC
//   GET    /api/ioc/stats      → Dashboard aggregated stats
//   GET    /api/ioc            → List all IOCs (paginated)
//   GET    /api/ioc/:id        → Single IOC details
//   DELETE /api/ioc/:id        → Archive IOC (admin only)
//   PATCH  /api/ioc/:id/flag   → Toggle false positive flag
// ============================================================

const express = require('express');
const router  = express.Router();

const {
  searchIOC,
  getAllIOCs,
  getIOCStats,
  getIOCById,
  deleteIOC,
  flagFalsePositive,
} = require('../controllers/iocController');

const { protect, authorize }    = require('../middleware/authMiddleware');
const { iocSearchLimiter }      = require('../middleware/rateLimitMiddleware');

// All IOC routes require authentication
router.use(protect);

// POST /api/ioc/search — extra rate limit to protect external API quota
router.post('/search', iocSearchLimiter, searchIOC);

// GET /api/ioc/stats — must be before /:id or 'stats' gets treated as an ID
router.get('/stats', getIOCStats);

// GET /api/ioc — list with filtering/pagination
router.get('/', getAllIOCs);

// GET /api/ioc/:id — single IOC
router.get('/:id', getIOCById);

// DELETE /api/ioc/:id — admin only
router.delete('/:id', authorize('admin'), deleteIOC);

// PATCH /api/ioc/:id/flag — any authenticated user can flag FPs
router.patch('/:id/flag', flagFalsePositive);

module.exports = router;
