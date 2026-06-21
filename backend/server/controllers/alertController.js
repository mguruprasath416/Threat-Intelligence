// ============================================================
// controllers/alertController.js — ALERT HISTORY CONTROLLER
// ============================================================

const Alert = require('../models/Alert');
const logger = require('../utils/logger');

// Fetch user's recent alerts (max 50) and unread counts
const getAlerts = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    const alerts = await Alert.find({ userId })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const unreadCount = await Alert.countDocuments({ userId, read: false });

    res.status(200).json({
      success: true,
      unreadCount,
      alerts
    });
  } catch (err) {
    logger.error(`Error in getAlerts: ${err.message}`);
    next(err);
  }
};

// Mark a single alert as read
const markAlertAsRead = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const alert = await Alert.findOneAndUpdate(
      { _id: id, userId },
      { $set: { read: true } },
      { new: true }
    );

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found or unauthorized'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Alert marked as read',
      alert
    });
  } catch (err) {
    logger.error(`Error in markAlertAsRead: ${err.message}`);
    next(err);
  }
};

// Mark all user's alerts as read
const markAllAlertsAsRead = async (req, res, next) => {
  try {
    const userId = req.user.userId;

    await Alert.updateMany(
      { userId, read: false },
      { $set: { read: true } }
    );

    res.status(200).json({
      success: true,
      message: 'All alerts marked as read'
    });
  } catch (err) {
    logger.error(`Error in markAllAlertsAsRead: ${err.message}`);
    next(err);
  }
};

// Delete a single alert
const deleteAlert = async (req, res, next) => {
  try {
    const userId = req.user.userId;
    const { id } = req.params;

    const alert = await Alert.findOneAndDelete({ _id: id, userId });

    if (!alert) {
      return res.status(404).json({
        success: false,
        message: 'Alert not found or unauthorized'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Alert deleted successfully'
    });
  } catch (err) {
    logger.error(`Error in deleteAlert: ${err.message}`);
    next(err);
  }
};

module.exports = {
  getAlerts,
  markAlertAsRead,
  markAllAlertsAsRead,
  deleteAlert
};
