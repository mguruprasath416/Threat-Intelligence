// ============================================================
// routes/alertRoutes.js — WATCHLIST ALERTS ROUTING
// ============================================================

const express = require('express');
const router = express.Router();
const { protect } = require('../middleware/authMiddleware');
const {
  getAlerts,
  markAlertAsRead,
  markAllAlertsAsRead,
  deleteAlert
} = require('../controllers/alertController');

// All alert routes require auth
router.use(protect);

router.route('/')
  .get(getAlerts);

router.route('/read-all')
  .post(markAllAlertsAsRead);

router.route('/:id/read')
  .patch(markAlertAsRead);

router.route('/:id')
  .delete(deleteAlert);

module.exports = router;
// ============================================================
