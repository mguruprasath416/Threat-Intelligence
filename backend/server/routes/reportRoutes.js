// ============================================================
// routes/reportRoutes.js — REPORT API ROUTES
// ============================================================
// POST   /api/reports              → Create report
// GET    /api/reports              → List reports (paginated)
// GET    /api/reports/:id          → Get single report + IOC details
// PUT    /api/reports/:id          → Update report
// POST   /api/reports/:id/publish  → Publish a draft report
// DELETE /api/reports/:id          → Delete (admin only)
// ============================================================

const express = require('express');
const router  = express.Router();

const {
  createReport,
  getAllReports,
  getReportById,
  updateReport,
  publishReport,
  deleteReport,
} = require('../controllers/reportController');

const { protect, authorize } = require('../middleware/authMiddleware');

// All report routes require authentication
router.use(protect);

router.post('/',              createReport);
router.get('/',               getAllReports);
router.get('/:id',            getReportById);
router.put('/:id',            updateReport);
router.post('/:id/publish',   publishReport);
router.delete('/:id',         authorize('admin'), deleteReport);

module.exports = router;
