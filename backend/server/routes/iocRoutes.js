// ============================================================
// routes/iocRoutes.js — UPDATED WITH POWER BI EXPORT
// ============================================================

const express = require('express');
const router  = express.Router();
const multer  = require('multer');
const path    = require('path');

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.csv', '.json'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only CSV and JSON files are allowed.'));
    }
  }
});

const {
  searchIOC,
  getAllIOCs,
  getIOCStats,
  getIOCById,
  deleteIOC,
  flagFalsePositive,
  getMitreCoverage,
  updateMitreTechniques,
  bulkImportIOCs,
  exportIOCs,
} = require('../controllers/iocController');

const {
  exportForPowerBI,
  exportStatsForPowerBI,
} = require('../controllers/powerbiController');

const { protect, authorize }    = require('../middleware/authMiddleware');
const { iocSearchLimiter }      = require('../middleware/rateLimitMiddleware');

// All IOC routes require authentication
router.use(protect);

// ── Existing routes ────────────────────────────────────────
router.post('/search',    iocSearchLimiter, searchIOC);
router.get('/stats',      getIOCStats);
router.get('/mitre/coverage', getMitreCoverage);
router.get('/',           getAllIOCs);
router.get('/:id',        getIOCById);
router.delete('/:id',     authorize('admin'), deleteIOC);
router.patch('/:id/flag',  flagFalsePositive);
router.patch('/:id/mitre', updateMitreTechniques);

// ── Bulk Import/Export Routes (NEW) ─────────────────────────
// POST /api/ioc/bulk-import → Upload CSV/JSON file for bulk import
// GET  /api/ioc/export      → Export IOCs to CSV with filters
router.post('/bulk-import', upload.single('file'), bulkImportIOCs);
router.get('/export',      exportIOCs);

// ── Power BI Export Routes (NEW) ───────────────────────────
// GET /api/ioc/export/powerbi       → all IOCs flat JSON
// GET /api/ioc/export/powerbi-stats → KPI stats for cards
router.get('/export/powerbi',       exportForPowerBI);
router.get('/export/powerbi-stats', exportStatsForPowerBI);

module.exports = router;