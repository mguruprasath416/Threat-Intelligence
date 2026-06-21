// ============================================================
// routes/authRoutes.js — AUTHENTICATION ROUTES (OTP)
// ============================================================
// POST /api/auth/send-otp    → Send OTP to email (step 1)
// POST /api/auth/verify-otp  → Verify OTP, receive JWT (step 2)
// GET  /api/auth/me          → Get my profile (protected)
// POST /api/auth/logout      → Clear auth cookie (protected)
// ============================================================

const express = require('express');
const router  = express.Router();

const { sendOtp, verifyOtp, getMe, logout } = require('../controllers/authController');
const { protect }     = require('../middleware/authMiddleware');
const { authLimiter } = require('../middleware/rateLimitMiddleware');

// Public routes
router.post('/send-otp',   authLimiter, sendOtp);
router.post('/verify-otp', authLimiter, verifyOtp);

// Protected routes (JWT required)
router.get('/me',      protect, getMe);
router.post('/logout', protect, logout);

module.exports = router;
